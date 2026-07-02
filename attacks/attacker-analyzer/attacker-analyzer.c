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

#include "sys/rtimer.h" /* added for RTIMER_SECOND */

/*
 * Alpha value for the EMA (Exponential Moving Average) method.
 * Small alpha -> smoother/more stable series (slower response).
 * Large alpha -> faster response (noisier).
 */
#ifndef ANALYZER_EMA_ALPHA
#define ANALYZER_EMA_ALPHA 0.05f /* alpha reduced for a more stable result */
#endif

/*
 * Warm-up: set to 0 by user decision (previously 180s). Telemetry emission now
 * starts from the beginning of the simulation (~4-12s after phase-offset);
 * there is no 3 min wait. WARNING: the TSCH-sync/DODAG-join transition rows
 * from 0-180s enter the dataset as is_attacker=0. This deliberately relaxes
 * the "do not teach the weird startup distribution as normal" hard-constraint
 * from CLAUDE.md. To revert, raise this value to 180 (or the desired seconds).
 * The energest counters are still reset before the first emission
 * (delta_tx/rx stay consistent).
 */
#ifndef ANALYZER_WARMUP_SECONDS
#define ANALYZER_WARMUP_SECONDS 0 /* warm-up disabled; log immediately */
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
/* Localization counters: incremented by uip6.c (forward) and 4emac.c
 * (broadcast); reset below on each telemetry emit (per-interval). */
unsigned long foure_fwd_in = 0;
unsigned long foure_fwd_out = 0;
unsigned long foure_bcast_tx = 0;
uint8_t blackhole_drop_prob_percent = 60;

/* Energest */
static uint64_t last_cpu = 0, last_lpm = 0, last_tx = 0, last_rx = 0;

/* Drift calculation variables */
static clock_time_t last_sync_time_ticks = 0;
static int32_t last_sync_drift_value = 0;
/* variable holding the stable average value for the EMA */
static float ema_long_term_drift_ppm = 0.0f;

/* flag to reset the energest baselines on the first real emission after warm-up */
static uint8_t energest_baselined = 0;


PROCESS_THREAD(attacker_analyzer_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();
  PROCESS_PAUSE();

  /*
   * Telemetry timer (initial setup):
   * - Warm-up: NO emission during the first ANALYZER_WARMUP_SECONDS s; we wait
   *   for TSCH sync, DODAG join and parent selection to complete.
   * - After warm-up, apply a ONE-TIME phase offset (0..8s) so that not all
   *   nodes emit at the same instant.
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
     * First iteration we wake up in after warm-up ends: reset the energest
     * counters so that the delta_tx/delta_rx of the next emission reflect only
     * the post-warm-up window. Do NOT emit in this iteration.
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
    
    /* Route table: total number of routes (downward routes)
     * In STORING mode: each node keeps its own route table
     * In NON_STORING mode: only the root has routes (0 on the others) */
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
            /* Same parent, do nothing */
        } else {
            parent_switch_count++;
            uip_ipaddr_copy(&last_parent_ip, parent_ip);
        }
      }
    }

    /* Drift computation is currently unused - disabled */

#endif

    /*
     * PACKET SIZE NOTE: Energest metrics and some instantaneous drift metrics
     * were removed to avoid exceeding the MTU limit.
     * TIMESTAMP: for ease of analysis, a timestamp in seconds is prepended to each packet.
     * APP_PACKET_COUNT: application layer packet count (for flooding attack detection)
     * ROUTE_COUNT: total number of routes in the route table (downward routes)
     * DELTA_TX/DELTA_RX: energest radio transmit/listen time deltas (ticks)
     */
    /* Localization attributes (per-interval):
     * forward_ratio = 100*forwarded/should-be-forwarded (Blackhole; 100 if no forwarder)
     * bcast_tx      = broadcast frames sent in this window (Shared Cell) */
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
    /* reset per-interval localization counters (for the next window) */
    foure_fwd_in = 0; foure_fwd_out = 0; foure_bcast_tx = 0;
    /*
     * Dynamic interval for the next telemetry emission:
     * - Widen the jitter: +/-50% -> [0.5*base, 1.5*base) uniform
     * - This wide range reduces queue and shared-slot collisions during busy moments.
     * - Emission frequency increased (16 -> 8 seconds) thanks to the buffer mechanism.
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

    /* Reset static variables */
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
