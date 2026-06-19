#include "contiki.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-udp-packet.h"
#include "sys/ctimer.h"
#include "random.h"

#include <stdio.h>
#include <string.h>

#include "net/ipv6/uiplib.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/link-stats.h"

#include "sys/log.h"
#define LOG_MODULE "AttackerAnalyzer"
#define LOG_LEVEL LOG_LEVEL_INFO

#include "sys/rtimer.h" /* RTIMER_SECOND icin eklendi */

/*
 * EMA (Exponential Moving Average) yontemi icin alfa degeri.
 * Kucuk alfa -> daha yumusak/stabil seri (gec tepki).
 * Buyuk alfa -> daha hizli tepki (daha gurultulu).
 */
#ifndef ANALYZER_EMA_ALPHA
#define ANALYZER_EMA_ALPHA 0.05f /* Daha stabil bir sonuc icin alfa kucultuldu */
#endif

/*
 * Warm-up: KULLANICI KARARI ile 0'a cekildi (eskiden 180s). Artik telemetri
 * yayini simulasyon basindan itibaren (faz-otelemesi sonrasi ~4-12s) baslar;
 * 3 dk bekleme yok. UYARI: 0-180s arasi TSCH-sync/DODAG-join gecis satirlari
 * is_attacker=0 olarak veri setine girer. Bu, CLAUDE.md'deki "garip baslangic
 * dagilimini normal diye ogretme" hard-constraint'ini bilerek geversiz kilar.
 * Geri almak icin bu degeri 180'e (veya istenen sn'ye) yukseltmek yeterli.
 * energest sayaclari yine ilk yayim oncesi sifirlanir (delta_tx/rx tutarli).
 */
#ifndef ANALYZER_WARMUP_SECONDS
#define ANALYZER_WARMUP_SECONDS 0 /* warm-up kapatildi; hemen logla */
#endif

#if TSCH_TIME_SYNCH
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/mac/4emac/4emac-private.h"
#endif /* TSCH_TIME_SYNCH */

#include "sys/energest.h"

#include "os/services/central-sch/cs-queue.h"
#include "net/mac/4emac/4erdc.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"
#include "net/linkaddr.h"
#include "net/ipv6/uip-ds6.h"

/* Extern declarations for global variables defined in rpl-icmp6.c */
extern uint32_t dio_sent_count;
extern uint32_t dao_sent_count;
extern uint32_t dis_sent_count;

/* Function Prototypes for external functions */
int32_t foure_rdc_get_last_packet_drift(void);
int32_t foure_scheduler_get_last_correction(void);
uint8_t foure_mac_buf_content_get_buffer_occupancy(linkaddr_t *linkaddr);


/*---------------------------------------------------------------------------*/
PROCESS(attacker_analyzer_process, "Attacker Analyzer process");
/*---------------------------------------------------------------------------*/

static int attacker_caller_type = 0;
static void *udp_conn_ptr = NULL;
static uip_ipaddr_t dest_ipaddr;
static uint16_t udp_port = 0;
static uint16_t parent_switch_count = 0;
static uip_ipaddr_t last_parent_ip;

/* Attacker information */
static int is_attacker = 0;
static int attack_type = ATTACK_TYPE_NONE;

/* Application layer packet count */
static unsigned int app_packet_count = 0;

/*
 * Blackhole forwarding drop hook globals.
 * Default: drop disabled. blackhole-attack-client.c sets these during
 * attack active windows; uip6.c reads them in forwarding decision.
 */
uint8_t blackhole_drop_forwards = 0;
/* Lokalizasyon sayaclari: uip6.c (forward) ve 4emac.c (broadcast) artirir,
 * her telemetri emit'inde asagida sifirlanir (per-interval). */
unsigned long foure_fwd_in = 0;
unsigned long foure_fwd_out = 0;
unsigned long foure_bcast_tx = 0;
uint8_t blackhole_drop_prob_percent = 60;

/* Energest */
static uint64_t last_cpu = 0, last_lpm = 0, last_tx = 0, last_rx = 0;

/* Drift calculation variables */
static clock_time_t last_sync_time_ticks = 0;
static int32_t last_sync_drift_value = 0;
/* EMA icin stabil ortalama degerini tutan degisken */
static float ema_long_term_drift_ppm = 0.0f;

/* Warm-up sonrasi ilk gercek yayimda energest baseline'larini sifirlamak icin bayrak */
static uint8_t energest_baselined = 0;


PROCESS_THREAD(attacker_analyzer_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();
  PROCESS_PAUSE();

  /*
   * Telemetri zamanlayicisi (ilk kurulum):
   * - Warm-up: ilk ANALYZER_WARMUP_SECONDS sn boyunca yayin YOK; TSCH sync,
   *   DODAG join ve parent secimi tamamlansin diye bekleriz.
   * - Warm-up'tan sonra TEK SEFERLIK faz otelemeyi uygula (0..8sn) ki
   *   tum dugumler ayni anda yayin yapmasin.
   */
  {
    clock_time_t base0 = (8 * CLOCK_SECOND);
    clock_time_t phase0 = (clock_time_t)(random_rand() % base0);
    clock_time_t warmup = (clock_time_t)ANALYZER_WARMUP_SECONDS * CLOCK_SECOND;
    etimer_set(&timer, warmup + phase0);
  }
  uip_create_unspecified(&last_parent_ip);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    /*
     * Warm-up bitiminde ilk uyandigimiz iterasyon: energest sayaclarini
     * sifirla ki sonraki yayinin delta_tx/delta_rx degerleri sadece
     * warm-up sonrasi pencereyi yansitsin. Bu iterasyonda yayim YAPMA.
     */
    if(!energest_baselined) {
      energest_flush();
      last_cpu = energest_type_time(ENERGEST_TYPE_CPU);
      last_lpm = energest_type_time(ENERGEST_TYPE_LPM);
      last_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
      last_rx = energest_type_time(ENERGEST_TYPE_LISTEN);
      energest_baselined = 1;
      {
        clock_time_t base = (8 * CLOCK_SECOND);
        clock_time_t jitter = (clock_time_t)(random_rand() % base);
        clock_time_t next = (base / 2) + jitter;
        if(next < 1) { next = 1; }
        etimer_set(&timer, next);
      }
      continue;
    }

    /* Energest delta calculation */
    energest_flush();
    uint64_t curr_cpu = energest_type_time(ENERGEST_TYPE_CPU);
    uint64_t curr_lpm = energest_type_time(ENERGEST_TYPE_LPM);
    uint64_t curr_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
    uint64_t curr_rx = energest_type_time(ENERGEST_TYPE_LISTEN);
    uint64_t delta_cpu = curr_cpu - last_cpu;
    uint64_t delta_lpm = curr_lpm - last_lpm;
    uint64_t delta_tx = curr_tx - last_tx;
    uint64_t delta_rx = curr_rx - last_rx;
    uint64_t delta_radio_total = delta_tx + delta_rx;
    last_cpu = curr_cpu;
    last_lpm = curr_lpm;
    last_tx = curr_tx;
    last_rx = curr_rx;

    /* Metric variables initialization */
    uint8_t buf[256];
    uint8_t node_id = linkaddr_node_addr.u8[LINKADDR_SIZE - 1];
    uint8_t parent_id = 0;
    uint8_t buf_occupancy = 0;
    uint16_t rank = 0;
    uint8_t tx_slot_count = 0;
    int16_t rssi = 0;
    uint8_t nbr_count = uip_ds6_nbr_num();
    int32_t anlik_drift = 0;
    int32_t correction_amount = 0;
    
    /* Route table: toplam route sayısı (downward routes)
     * STORING modda: her düğüm kendi route table'ını tutar
     * NON_STORING modda: sadece root'ta route var (diğerlerinde 0) */
    uint8_t route_count = uip_ds6_route_num_routes();

#if TSCH_TIME_SYNCH
    rpl_dag_t *dag = rpl_get_any_dag();
    if(dag != NULL) {
      rank = dag->rank;
      if(dag->preferred_parent) {
        const uip_ipaddr_t *parent_ip = rpl_parent_get_ipaddr(dag->preferred_parent);
        parent_id = parent_ip->u8[15];
        const linkaddr_t *parent_lladdr = rpl_get_parent_lladdr(dag->preferred_parent);

        if(parent_lladdr != NULL) {
            const struct link_stats *stats = link_stats_from_lladdr(parent_lladdr);
            if(stats != NULL) {
                rssi = stats->rssi;
            }
            buf_occupancy = foure_mac_buf_content_get_buffer_occupancy((linkaddr_t *)parent_lladdr);
            tx_slot_count = foure_mac_buf_slot_get_num_from_linkaddr(
                (linkaddr_t *)parent_lladdr, SLOT_TYPE_TRANSMIT, SLOT_UNLOCK);
        }

        if(uip_ipaddr_cmp(&last_parent_ip, parent_ip)) {
            // Aynı parent, bir şey yapma
        } else {
            parent_switch_count++;
            uip_ipaddr_copy(&last_parent_ip, parent_ip);
        }
      }
    }

    /* Drift hesaplaması şuan kullanılmıyor - devre dışı bırakıldı */
    /*
    anlik_drift = foure_rdc_get_last_packet_drift();
    correction_amount = foure_scheduler_get_last_correction();
    
    clock_time_t current_ticks = clock_time();
    if(anlik_drift != last_sync_drift_value) {
        if(last_sync_time_ticks > 0) {
          clock_time_t elapsed_ticks = current_ticks - last_sync_time_ticks;
          if(elapsed_ticks >= CLOCK_SECOND) {
            float elapsed_seconds = (float)elapsed_ticks / CLOCK_SECOND;
            int32_t delta_drift = anlik_drift - last_sync_drift_value;
            float instant_ppm = (((float)delta_drift * 1000000.0f) / RTIMER_SECOND) / elapsed_seconds;
            ema_long_term_drift_ppm = (ANALYZER_EMA_ALPHA * (instant_ppm)) + ((1.0f - ANALYZER_EMA_ALPHA) * ema_long_term_drift_ppm);
          }
        }
        last_sync_time_ticks = current_ticks;
        last_sync_drift_value = anlik_drift;
    }
    */

#endif

    /*
     * PAKET BOYUTU NOTU: Energest metrikleri ve bazi anlik drift metrikleri,
     * MTU limitini asmamak adina kaldirilmistir.
     * ZAMAN DAMGASI: Analiz kolayligi icin her paketin basina saniye cinsinden zaman damgasi eklenmistir.
     * APP_PACKET_COUNT: Application layer paket sayimi (flooding saldirisi tespiti icin)
     * ROUTE_COUNT: Route table'daki toplam route sayısı (downward routes)
     * DELTA_TX/DELTA_RX: Energest radyo gonderim/dinleme zaman farklari (ticks)
     */
    /* Lokalizasyon oznitelikleri (per-interval):
     * forward_ratio = 100*iletilen/iletilmesi-gereken (Blackhole; ileten-yoksa 100)
     * bcast_tx      = bu pencerede gonderilen yayin cercevesi (Shared Cell) */
    unsigned int forward_ratio = (foure_fwd_in > 0)
        ? (unsigned int)((100UL * foure_fwd_out) / foure_fwd_in) : 100;
    if(forward_ratio > 100) { forward_ratio = 100; }
    unsigned long bcast_tx = foure_bcast_tx;

    int buflen = snprintf((char *)buf, sizeof(buf), " %lu,%u,%u,%u,%u,%lu,%lu,%lu,%u,%u,%u,%d,%u,%lu,%lu,%u,%u,%lu,%d,%d ",
      clock_seconds(),
      node_id, parent_id, rank, buf_occupancy,
      dio_sent_count, dao_sent_count, dis_sent_count,
      nbr_count, tx_slot_count, parent_switch_count,
      rssi,
      route_count, (unsigned long)delta_tx, (unsigned long)delta_rx,
      app_packet_count, forward_ratio, bcast_tx, is_attacker, attack_type);

    if(buflen >= 0 && buflen < sizeof(buf)) {
        if(attacker_caller_type == 0) {
            // Client (as per attacker-analyzer-old.c)
            simple_udp_sendto((struct simple_udp_connection *)udp_conn_ptr, buf, buflen, &dest_ipaddr);
        } else {
            // Server
            uip_udp_packet_sendto((struct uip_udp_conn *)udp_conn_ptr, buf, buflen, &dest_ipaddr, UIP_HTONS(udp_port));
        }
    }
    /* per-interval lokalizasyon sayaclarini sifirla (sonraki pencere icin) */
    foure_fwd_in = 0; foure_fwd_out = 0; foure_bcast_tx = 0;
    /*
     * Bir sonraki telemetri gonderimi icin dinamik aralik:
     * - Jitter'i genislet: ±50% -> [0.5*base, 1.5*base) uniform
     * - Bu genis aralik, yogun anlarda kuyruk ve paylasimli slot cakismalarini azaltir.
     * - Gonderim sikligi artirildi (16 -> 8 saniye) buffer mekanizmasi sayesinde.
     */
    {
      clock_time_t base = (8 * CLOCK_SECOND);
      clock_time_t jitter = (clock_time_t)(random_rand() % base); /* [0, base) */
      clock_time_t next = (base / 2) + jitter; /* [0.5*base, 1.5*base) */
      if(next < 1) { next = 1; }
      etimer_set(&timer, next);
    }
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
void
attacker_analyzer_init(int caller_type, void *conn, void *ipaddr, unsigned short port, int p_is_attacker, int p_attack_type)
{
    attacker_caller_type = caller_type;
    udp_conn_ptr = conn;
    uip_ipaddr_copy(&dest_ipaddr, (uip_ipaddr_t *)ipaddr);
    udp_port = (uint16_t)port;
    is_attacker = p_is_attacker;
    attack_type = p_attack_type;

    /* Statik degiskenleri sifirla */
    last_sync_time_ticks = 0;
    last_sync_drift_value = 0;
    ema_long_term_drift_ppm = 0.0f;
    energest_baselined = 0;

    process_exit(&attacker_analyzer_process);
    process_start(&attacker_analyzer_process, NULL);
    printf("attacker_analyzer_process init with attack mode: is_attacker=%d, attack_type=%d\n", is_attacker, attack_type);
}
/*---------------------------------------------------------------------------*/
void
attacker_analyzer_set_attack_mode(int p_is_attacker, int p_attack_type)
{
  is_attacker = p_is_attacker;
  attack_type = p_attack_type;
  printf("attacker_analyzer_process updated attack mode: is_attacker=%d, attack_type=%d\n", is_attacker, attack_type);
}
/*---------------------------------------------------------------------------*/
void
attacker_analyzer_set_app_packet_count(unsigned int packet_count)
{
  app_packet_count = packet_count;
}
/*---------------------------------------------------------------------------*/
uint32_t
attacker_pack_app_pkt(uint32_t count)
{
  uint32_t mid = (uint32_t)linkaddr_node_addr.u8[LINKADDR_SIZE - 1];
  return (mid << 24) | (count & UINT32_C(0x00FFFFFF));
}
/*---------------------------------------------------------------------------*/
uint32_t
attacker_unpack_src_id(uint32_t packed)
{
  return (packed >> 24) & UINT32_C(0xFF);
}
/*---------------------------------------------------------------------------*/
uint32_t
attacker_unpack_count(uint32_t packed)
{
  return packed & UINT32_C(0x00FFFFFF);
}
/*---------------------------------------------------------------------------*/
