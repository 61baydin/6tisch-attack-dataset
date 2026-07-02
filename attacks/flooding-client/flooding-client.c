#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "arch/dev/cc2420/cc2420.h"
#include "net/mac/4emac/4emac-private.h"

#include "sys/log.h"
#define LOG_MODULE "UDPClient"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/*
 * Two-phase sending - 30-min headless run scheme:
 *  - First 3 min warmup (attacker-analyzer suppresses it),
 *  - Switch to attack phase at minute 3 (flooding is routing-independent).
 * ATTACK_SEND_INTERVAL stealth knob: 1s is very aggressive and leaves an
 * overwhelming signature in the app_packet_count and delta_tx features. With
 * a 4s default we widen the overlap region with normal nodes (15s interval).
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)
#define NORMAL_SEND_INTERVAL   (15 * CLOCK_SECOND)
/*
 * Stealth v4 (revert): active/passive windows removed.
 * The v3 burst design (30s active + 90s passive) raised the average rate to
 * only 62% above normal nodes - it was not a real flood, just "slightly fast
 * normal traffic". Because the attack's passive phases hid the attacker, the
 * combined binary recall came out at 0.30, but this was not detection
 * difficulty, it was a lack of attack.
 *
 * 4s -> 1s (user request, deliberate choice): 60 pkt/min vs normal 4 pkt/min
 * = 15x load. Very aggressive; leaves an overwhelming signature in
 * app_packet_count/delta_tx, and App Flooding detection may be trivial
 * (~1.0 F1). This conflicts with the "not trivial" dataset goal; it was
 * requested as a full change rather than a severity gradient.
 */
#ifndef ATTACK_SEND_INTERVAL_S
#define ATTACK_SEND_INTERVAL_S 1
#endif
#define ATTACK_SEND_INTERVAL   (ATTACK_SEND_INTERVAL_S * CLOCK_SECOND)

#define JRC_IP_ADDR { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 } //
uip_ipaddr_t jrc_ip_addr; //

static struct simple_udp_connection udp_conn;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
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
  unsigned count = *(unsigned *)data;
  LOG_INFO("Received response %u from ", count);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
}
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

  /* Manually add the fd00::5 address */
  uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);

  /* Start the UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);
  
  foure_timesynch_init(0);
  ////////////////////
  /* First phase label: no attack (0, ATTACK_TYPE_NONE) */
  attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr, (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);
  ////////////////////
  /* Start in the normal phase */
  start_time = clock_time();
  in_attack_phase = 0;
  phase1_duration = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
  LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(phase1_duration / CLOCK_SECOND));
  etimer_set(&periodic_timer, (clock_time_t)(random_rand() % NORMAL_SEND_INTERVAL));

  printf("udp_bind()\n");

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    /* Determine the current phase and interval */
    clock_time_t elapsed = clock_time() - start_time;
    uint8_t new_phase = (elapsed >= phase1_duration);
    if(new_phase && !in_attack_phase) {
      in_attack_phase = 1;
      LOG_INFO("Switching to attack phase (burst window)\n");
      /* Update the label to attack: 1, ATTACK_TYPE_FLOODING */
      attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_FLOODING);
    }
    clock_time_t current_interval = in_attack_phase ? ATTACK_SEND_INTERVAL : NORMAL_SEND_INTERVAL;

    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      /* Send to DAG root */
      LOG_INFO("Sending request %u to ", count);
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
      LOG_INFO("Not reachable yet\n");
    }

    /* Add jitter */
    etimer_set(&periodic_timer, current_interval - CLOCK_SECOND + (clock_time_t)(random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
} 
/*---------------------------------------------------------------------------*/