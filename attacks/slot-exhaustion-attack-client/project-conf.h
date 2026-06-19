/*
 * Copyright (c) 2015, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

 #ifndef PROJECT_CONF_H_
 #define PROJECT_CONF_H_
 
 #ifdef APP_CONF_H
 #include APP_CONF_H
 #endif /* APP_CONF_H */
 
 /* USB serial takes space, free more space elsewhere */
 #define SICSLOWPAN_CONF_FRAG 0
 #define UIP_CONF_BUFFER_SIZE 160
 
 /*******************************************************/
 /******************* Configure TSCH ********************/
 /*******************************************************/
 
 #ifndef WITH_SECURITY
 #define WITH_SECURITY 0
 #endif /* WITH_SECURITY */
 
 #define IEEE802154_CONF_PANID 0xbaba
 #define FOURE802154_CONF_PANID IEEE802154_CONF_PANID
 
 #define SLOT_CONF_FRAME_SIZE 21
 
 #define FOURE_CONF_KA_ENABLED 1
 #define FOURE_CONF_KA_INTERVAL (2 * CLOCK_SECOND)
 
 #if WITH_SECURITY
 #define LLSEC802154_CONF_ENABLED 1
 #define FOURE_CONF_DEFAULT_TIMESLOT_LENGTH 45000
 #define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1
 #define LLSEC802154_CONF_USES_FRAME_COUNTER 0
 #define LLSEC802154_CONF_USES_AUX_HEADER    1
 #endif /* WITH_SECURITY */
 
 #ifndef FOURE_CONF_DEFAULT_TIMESLOT_LENGTH
 #define FOURE_CONF_DEFAULT_TIMESLOT_LENGTH 15000
 #endif /* FOURE_CONF_DEFAULT_TIMESLOT_LENGTH */
 
 #ifndef UIP_CONF_MAX_ROUTES
 #define UIP_CONF_MAX_ROUTES          10
 #endif
 
 #ifndef NBR_TABLE_CONF_MAX_NEIGHBORS
 #define NBR_TABLE_CONF_MAX_NEIGHBORS 7
 #endif
 
 #define FOURE_CONF_MAX_CONTENT 10
 /* Per-destination cell cap set to 50, well above the natural traffic-driven
  * allocation (~5 cells/neighbor) yet within exp5438 RAM limits. A low cap
  * (e.g. 10) artificially pre-empts the 6P Cell Allocation Exhaustion attack
  * by NACKing every ADD after a handful of cells. 6P (RFC 8480) and MSF
  * (RFC 9033) impose no fixed per-destination cap, so this value is an
  * implementation-side memory bound, not a protocol constraint. */
 #define FOURE_CONF_MAX_SLOTS_PER_DESTINATION 10
 #define SIXTOP_SERIAL_COMMANDS_ENABLE 1
 
 /*******************************************************/
 /************* RPL Ayarları (Sadece Router) ************/
 /*******************************************************/
 #undef UIP_CONF_ROUTER
 #define UIP_CONF_ROUTER 1
 #undef RPL_CONF_WITH_ROOT
 #define RPL_CONF_WITH_ROOT 0
#undef WITH_NON_STORING
#define WITH_NON_STORING 0

#if WITH_NON_STORING
#undef RPL_NS_CONF_LINK_NUM
#define RPL_NS_CONF_LINK_NUM 0  // Client'lar için 0 (root'ta 40)
#undef UIP_CONF_MAX_ROUTES
#define UIP_CONF_MAX_ROUTES 0
#undef RPL_CONF_MOP
#define RPL_CONF_MOP RPL_MOP_NON_STORING
#endif
 
 /*******************************************************/
 /************* Other system configuration **************/
 /*******************************************************/
 /*
#define LOG_CONF_LEVEL_TCPIP                       LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_IPV6                        LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_6LOWPAN                     LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_MAC                         LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_FRAMER                      LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_4EMAC                       LOG_LEVEL_INFO
 */
 #endif /* PROJECT_CONF_H_ */
 