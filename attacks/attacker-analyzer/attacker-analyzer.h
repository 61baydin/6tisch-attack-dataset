
#ifndef ATTACKER_ANALYZER_H_
#define ATTACKER_ANALYZER_H_

#include <stdint.h>

/* Attack Types */
#define ATTACK_TYPE_NONE 0
#define ATTACK_TYPE_BLACKHOLE 1 
#define ATTACK_TYPE_DECREASE_RANK 2 
#define ATTACK_TYPE_DIS 3 
#define ATTACK_TYPE_FLOODING 4
#define ATTACK_TYPE_SHARED_SLOT 5 
#define ATTACK_TYPE_SLOT_EXHAUSTION 6
/* ATTACK_TYPE_TIMEKEEP: tarihsel ad. Gercekte kanal-atlama-sirasi (channel
 * hopping sequence) IE'sini bozan EB-poisoning saldirisidir, ASN/zaman-sync
 * IE'si degil. Yayinda "channel-hopping-sequence EB poisoning" denmeli. */
#define ATTACK_TYPE_TIMEKEEP 7

void attacker_analyzer_init(int caller_type, void *conn, void *ipaddr, unsigned short port, int is_attacker, int attack_type);
void attacker_analyzer_set_attack_mode(int is_attacker, int attack_type);
void attacker_analyzer_set_app_packet_count(unsigned int packet_count);

/*
 * Blackhole forwarding drop hook flags.
 *
 * Set blackhole_drop_forwards=1 to enable silent dropping of forwarded
 * (non-locally-originated) packets in uip6.c. blackhole_drop_prob_percent
 * controls the per-packet drop probability (0-100). The hook is in
 * uip_process() forwarding branch.
 *
 * Bu blackhole'un literatür-uyumlu klasik davranisidir: saldirgan paketleri
 * sessizce dusurur (forward etmez). Ucu route_count yuksek + delta_tx dusuk
 * imzasi yaratir, telemetri-bazli tespit mumkun olur.
 */
extern uint8_t blackhole_drop_forwards;
extern uint8_t blackhole_drop_prob_percent;

/* Saldirgan-dugum lokalizasyonu icin per-interval sayaclar (analyzer her emit'te sifirlar):
 *  foure_fwd_in/out -> forward_ratio (Blackhole): iletilmesi-gereken vs gercekten-iletilen
 *  foure_bcast_tx   -> bcast_tx (Shared Cell): gonderilen yayin cercevesi sayisi */
extern unsigned long foure_fwd_in;
extern unsigned long foure_fwd_out;
extern unsigned long foure_bcast_tx;

/*
 * App-packet payload encoding helpers.
 *
 * To enable robust per-source PDR computation at the sink, the app packet
 * payload (4 bytes = uint32_t) carries both the local sender count and an
 * explicit mote-id byte. Layout (host endian):
 *
 *   bits 31..24 : src_mote_id (last byte of LL address)
 *   bits 23.. 0 : count (low 24 bits of sender's monotonic counter)
 *
 * NOTE for MSP430 / 16-bit platforms: uint32_t is required because
 * `unsigned int` is 16-bit on MSP430.
 *
 * Implementation is in attacker-analyzer.c to avoid dragging in
 * net/linkaddr.h (and its clock.h dependency) at every include site.
 */
uint32_t attacker_pack_app_pkt(uint32_t count);
uint32_t attacker_unpack_src_id(uint32_t packed);
uint32_t attacker_unpack_count(uint32_t packed);

#endif /* ATTACKER_ANALYZER_H_ */