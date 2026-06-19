/*
 * Border Router for Contiki-NG (SLIP + RPL Root)
 */
#include "contiki.h"
#include <stdint.h>
#include "net/netstack.h"
#include "net/ipv6/uip-ds6.h"
#include "net/routing/routing.h"
#include "net/ipv6/uip-udp-packet.h"
#include "sys/log.h"
#include "net/app-layer/attack-analyzer/attacker-analyzer.h"

#define LOG_MODULE "BR"
#define LOG_LEVEL LOG_LEVEL_INFO
#define TIMER_NEIGHBOR_MAX_INTERVAL (60 * CLOCK_SECOND)
#define UDP_SERVER_PORT 5678
#define WITH_SERVER_REPLY 1

#define JRC_IP_ADDR { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }

PROCESS(border_router_process, "Border Router");
AUTOSTART_PROCESSES(&border_router_process);

uip_ipaddr_t jrc_ip_addr; 

PROCESS_THREAD(border_router_process, ev, data)
{
  static struct uip_udp_conn *client_conn = NULL;
  //uint8_t buf[100]; // 100 byte channel parametres request
  static struct etimer neighbor_duration_timer;
  /* Sink-side cumulative app-packet rx counter; serialised into telemetry
   * column 16 (app_packet_count) so the host listener captures it without
   * extra packet types. Pairs with sender-side counts emitted by clients. */
  static unsigned int app_rx_count = 0;
  PROCESS_BEGIN();

  /* Manuel olarak fd00::5 adresini ekle */
  uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);

  /* Initialize SLIP interface (done automatically in Contiki-NG border router) */
  /* Start RPL root */
  NETSTACK_ROUTING.root_start();

  LOG_INFO("Border router started as RPL root.\n");

  /* Print our IPv6 addresses */
  int i;
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    if(uip_ds6_if.addr_list[i].isused) {
      LOG_INFO("IPv6: ");
      LOG_INFO_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      LOG_INFO("\n");
    }
  }
  etimer_set(&neighbor_duration_timer, TIMER_NEIGHBOR_MAX_INTERVAL);

  client_conn = udp_new(NULL, 0, NULL);
  if(client_conn == NULL) {
    printf("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_SERVER_PORT)); 

////////////////////
  attacker_analyzer_init(1, client_conn, (void *)&jrc_ip_addr, (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);
////////////////////
  while (1){

    PROCESS_YIELD();
    if(ev == tcpip_event) {
      if(uip_newdata()) {
        uint32_t packed = 0;
        uint32_t count = 0;
        if(uip_datalen() >= sizeof(packed)) {
          memcpy(&packed, uip_appdata, sizeof(packed));
          count = attacker_unpack_count(packed);
        }
        app_rx_count++;
        attacker_analyzer_set_app_packet_count(app_rx_count);
        LOG_INFO("Received request %lu from ", (unsigned long)count);
        LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
        LOG_INFO(" (sink_rx_total=%u)\n", app_rx_count);
#if WITH_SERVER_REPLY
        LOG_INFO("Sending response %lu to ", (unsigned long)count);
        LOG_INFO_6ADDR(&UIP_IP_BUF->srcipaddr);
        LOG_INFO("\n");
        uip_udp_packet_sendto(client_conn, &count, sizeof(count),
                              &UIP_IP_BUF->srcipaddr, UIP_UDP_BUF->srcport);
#endif
      }
    }
    if(etimer_expired(&neighbor_duration_timer)){
      printf("CoAP: Send to %u\n", jrc_ip_addr.u8[15]);
      etimer_set(&neighbor_duration_timer, TIMER_NEIGHBOR_MAX_INTERVAL);
    }

  }


  PROCESS_END();
}