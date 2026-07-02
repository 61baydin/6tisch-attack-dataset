/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
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
 *
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#ifdef APP_CONF_H
#include APP_CONF_H
#endif /* APP_CONF_H */

#ifndef WEBSERVER_CONF_CFS_CONNS
#define WEBSERVER_CONF_CFS_CONNS 2
#endif

#ifndef BORDER_ROUTER_CONF_WEBSERVER
#define BORDER_ROUTER_CONF_WEBSERVER 0
#endif

#if BORDER_ROUTER_CONF_WEBSERVER
#define UIP_CONF_TCP 1
#endif

/* USB serial takes space, free more space elsewhere */
#define SICSLOWPAN_CONF_FRAG 0

#ifndef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE    200
#endif

#ifndef UIP_CONF_RECEIVE_WINDOW
#define UIP_CONF_RECEIVE_WINDOW  60
#endif

#define RPL_CONF_OF_OCP  RPL_OCP_TSCH // added

/*******************************************************/
/******************* Configure TSCH ********************/
/*******************************************************/
/* Set to enable TSCH security */
#ifndef WITH_SECURITY
#define WITH_SECURITY 0
#endif /* WITH_SECURITY */

/* IEEE802.15.4 PANID */
#define IEEE802154_CONF_PANID 0xbaba

#if WITH_SECURITY
/* Enable security */
#define LLSEC802154_CONF_ENABLED 1

#if LLSEC802154_CONF_ENABLED
#define FOURE_CONF_DEFAULT_TIMESLOT_LENGTH 45000

#define LLSEC802154_CONF_USES_EXPLICIT_KEYS 1
#define LLSEC802154_CONF_USES_FRAME_COUNTER 0
#define LLSEC802154_CONF_USES_AUX_HEADER    1
#endif /* LLSEC802154_CONF_ENABLED */
#endif /* WITH_SECURITY */

#ifndef FOURE_CONF_DEFAULT_TIMESLOT_LENGTH
#define FOURE_CONF_DEFAULT_TIMESLOT_LENGTH 15000
#endif /* FOURE_CONF_DEFAULT_TIMESLOT_LENGTH */

#ifndef UIP_CONF_MAX_ROUTES
#define UIP_CONF_MAX_ROUTES          10 // added, default 50
#endif

#ifndef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS 7 // added, default 10
#endif

#ifndef UIP_FALLBACK_INTERFACE
#define UIP_FALLBACK_INTERFACE 1  // added, enabled for tunslip listening
#endif

#define SLOT_CONF_FRAME_SIZE       21
#define FOURE_CONF_HARD_SLOTS      { {0, 0, (SLOT_TYPE_TIMEKEEP)}, {8, 0, (SLOT_TYPE_SHARED)}, {18, 0, (SLOT_TYPE_SHARED)} }

#define FOURE_CONF_MAX_CONTENT 10
#define FOURE_CONF_MAX_SLOTS_PER_DESTINATION 10

/*******************************************************/
/************* RPL Root and Non-Storing Settings *******/
/*******************************************************/
#undef UIP_CONF_ROUTER
#define UIP_CONF_ROUTER 1
#undef RPL_CONF_WITH_ROOT
#define RPL_CONF_WITH_ROOT 1

#undef WITH_NON_STORING
#define WITH_NON_STORING 0

#if WITH_NON_STORING
#undef RPL_NS_CONF_LINK_NUM
#define RPL_NS_CONF_LINK_NUM 40
#undef UIP_CONF_MAX_ROUTES
#define UIP_CONF_MAX_ROUTES 0
#undef RPL_CONF_MOP
#define RPL_CONF_MOP RPL_MOP_NON_STORING
#endif

/*******************************************************/
/************* Other system configuration **************/
/*******************************************************/

/* Logging */

#define LLSEC802154_CONF_ENABLED 0
#define LINK_STATS_CONF_ENABLED 1

#endif /* PROJECT_CONF_H_ */
