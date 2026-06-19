#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "arch/dev/cc2420/cc2420.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"

#include "sys/log.h"
#define LOG_MODULE "DecreaseRank"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/*
 * Two-phase operation aligned with the 30-min headless run scheme
 * (CLAUDE.md: 0-3 min warmup is suppressed by attacker-analyzer; this
 * client does 2 more min of normal traffic so it can join the DODAG
 * and attract child routes; switches to attack at 5 min sim time).
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)
#define NORMAL_SEND_INTERVAL   (15 * CLOCK_SECOND)

/*
 * Stealth knob: rank manipulation magnitude. The original 32 was
 * aggressively low ("VERY AGGRESSIVE - Maximum impact!") which made
 * the attacker an obvious DAG outlier. Smaller offsets (4..16) still
 * pull traffic toward the attacker but produce less obvious rank-vs-depth
 * fingerprints in the telemetry.
 */
/*
 * Stealth v4 (geri donus): 4 -> 8. v3'teki offset=4 RPL rank
 * hysteresis'inin (~32-128) altinda kaldigindan hicbir komsu parent
 * degistirmiyordu - saldiri kozmetik kalmisti. 8 v2 seviyesi: gercek
 * cocuk cekimi olusturur. v1'in 32'si "maksimum agresif" idi; 8 sinir.
 */
#ifndef DECREASE_RANK_OFFSET
#define DECREASE_RANK_OFFSET 8
#endif

#define JRC_IP_ADDR { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }
uip_ipaddr_t jrc_ip_addr;

static struct simple_udp_connection udp_conn;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "Decrease Rank Attack Client");
AUTOSTART_PROCESSES(&udp_client_process);
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
  LOG_INFO("DRANK: Received response, ignoring.\n");
}
/*---------------------------------------------------------------------------*/
/* No need for force_decrease_rank() anymore!
 * RPL OF will handle rank manipulation automatically when flag is set.
 */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static unsigned count;
  uip_ipaddr_t dest_ipaddr;
  static clock_time_t start_time;
  static uint8_t in_attack_phase;
  static clock_time_t phase1_duration;

  PROCESS_BEGIN();

  printf("==============================================\n");
  printf("DECREASE RANK ATTACK CLIENT STARTED\n");
  printf("Phase 1: Normal operation for 15 minutes\n");
  printf("Phase 2: Decrease rank attack with telemetry\n");
  printf("==============================================\n");

  /* Manuel olarak fd00::5 adresini ekle */
  uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);

  /* UDP baglantisini baslat */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);
  
  foure_timesynch_init(0);
  
  /* Ilk fazda etiket: ataksiz (0, ATTACK_TYPE_NONE) */
  attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr, (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);
  
  /* Normal fazda basla */
  start_time = clock_time();
  in_attack_phase = 0;
  phase1_duration = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
  LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(phase1_duration / CLOCK_SECOND));
  count = 0;
  etimer_set(&periodic_timer, (clock_time_t)(random_rand() % NORMAL_SEND_INTERVAL));

  printf("DRANK: udp_bind() completed\n");
  LOG_INFO("DRANK: Waiting for network join...\n");

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    /* Check if we should enter attack phase */
    clock_time_t elapsed = clock_time() - start_time;
    uint8_t new_phase = (elapsed >= phase1_duration);
    if(new_phase && !in_attack_phase) {
      in_attack_phase = 1;
      printf("==============================================\n");
      printf("*** ATTACK PHASE STARTED ***\n");
      printf("RPL OF will automatically manipulate rank!\n");
      printf("==============================================\n");
      LOG_INFO("DRANK: Switching to DECREASE RANK attack mode\n");
      
      /* Enable decrease rank attack in RPL OF layer (stealth offset). */
      rpl_decrease_rank_attack_enabled = 1;
      rpl_decrease_rank_target_offset = DECREASE_RANK_OFFSET;
      
      /* Force RPL to recalculate rank immediately */
      rpl_dag_t *dag = rpl_get_any_dag();
      if(dag != NULL && dag->instance != NULL) {
        rpl_reset_dio_timer(dag->instance);
        LOG_INFO("DRANK: Attack enabled in RPL OF, DIO triggered\n");
      }
      
      /* Etiketi saldiri olarak guncelle: 1, ATTACK_TYPE_DECREASE_RANK */
      attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_DECREASE_RANK);
    }

    /* Send telemetry packets */
    if(etimer_expired(&periodic_timer)) {
      if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
        /* Send to DAG root */
        rpl_dag_t *dag = rpl_get_any_dag();
        uint16_t current_rank = (dag != NULL) ? dag->rank : 0;
        
        if(in_attack_phase) {
          LOG_INFO("DRANK: [ATTACK] Sending packet %u to ", count);
        } else {
          LOG_INFO("DRANK: [NORMAL] Sending packet %u to ", count);
        }
        LOG_INFO_6ADDR(&dest_ipaddr);
        LOG_INFO_(" Rank=%u\n", current_rank);
        
        {
          uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
          simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
        }
        count++;

        /* Update packet count for analyzer */
        attacker_analyzer_set_app_packet_count(count);
      } else {
        if(in_attack_phase) {
          LOG_INFO("DRANK: [ATTACK] Not reachable yet\n");
        } else {
          LOG_INFO("DRANK: [NORMAL] Not reachable yet\n");
        }
      }

      /* Jitter ekle */
      etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND + (clock_time_t)(random_rand() % (2 * CLOCK_SECOND)));
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
