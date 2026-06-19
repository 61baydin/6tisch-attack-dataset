# Timekeep Slot Attack Client

## Açıklama

Bu client, TIMEKEEP slot'larına saldıran bir attack client'ıdır. TIMEKEEP slot'ları zaman senkronizasyonu için kullanılan özel slot'lardır ve EB (Enhanced Beacon) mesajları bu slot'larda gönderilir.

## Saldırı Mekanizması

- **Hedef:** `SLOT_TYPE_TIMEKEEP` slot'ları
- **Yöntem:** Sürekli EB (Enhanced Beacon) mesajları göndererek TIMEKEEP slot'larını meşgul etmek
- **Etki:** 
  - Zaman senkronizasyonunu bozar
  - Yeni node'ların ağa katılımını engeller
  - TIMEKEEP slot'larında çarpışmalar oluşturur

## Çalışma Prensibi

1. **Normal Faz (30 dakika):** Normal UDP paketleri gönderir
2. **Saldırı Fazı:** Her 500ms'de bir EB mesajı gönderir
3. **EB Mesajları:** `SLOT_TYPE_TIMEKEEP` slot'larına gönderilir
4. **Etki:** TIMEKEEP slot'ları meşgul olur, zaman senkronizasyonu bozulur

## Derleme

```bash
cd examples/tsch/rpl-udp/timekeep-attack-client
make TARGET=exp5438
```

## Kullanım

Cooja simülasyonunda bu client'ı kullanarak TIMEKEEP slot saldırısı yapabilirsiniz.

## Notlar

- EB mesajları broadcast olarak gönderilir
- TIMEKEEP slot'ları hard slot'lardır (sabit)
- Saldırı zaman senkronizasyonunu bozabilir
- Yeni node'ların ağa katılımı engellenebilir

