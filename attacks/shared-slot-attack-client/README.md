# Border Router Client/Server Örneği

Bu örnek, border router (0x5 adresi) ile iletişim kurmak için tasarlanmış UDP client ve server uygulamalarını içerir.

## Dosya Yapısı

```
border-router-client/
├── border-router-client.c    # Border router'a mesaj gönderen client
├── Makefile
└── README.md

border-router-server/
├── border-router-server.c    # Border router'da çalışan server
├── Makefile
└── README.md
```

## Kullanım

### 1. Border Router Server'ı Çalıştırma

Border router'da (tunslip6 ile bağlı cihazda):

```bash
cd examples/tsch/rpl-udp/border-router-server
make clean
make TARGET=sky
```

### 2. Border Router Client'ı Çalıştırma

Ağdaki diğer node'larda:

```bash
cd examples/tsch/rpl-udp/border-router-client
make clean
make TARGET=sky
```

### 3. Tunslip6 Bağlantısı

Border router ile host arasında bağlantı kurmak için:

```bash
sudo ./tunslip6 -a 127.0.0.1 -p 60001 fd00::5/64
```

## Özellikler

- **Client**: Her 15 saniyede bir border router'a (fd00::5) mesaj gönderir
- **Server**: Gelen mesajları alır ve yanıt gönderir
- **Port**: UDP_CLIENT_PORT=8765, UDP_SERVER_PORT=5678
- **Hedef Adres**: fd00::5 (border router)

## Mesaj Formatı

- Gönderilen mesaj: `unsigned count` (4 byte)
- Yanıt mesajı: Aynı `count` değeri

## Log Mesajları

Client log'ları:
- "Border router'a istek gönderiliyor: X, hedef: fd00::5"
- "Border router'dan yanıt alındı: X, gönderen: fd00::5"

Server log'ları:
- "Border router client'tan istek alındı: X, gönderen: [client_addr]"
- "Yanıt gönderiliyor: X, hedef: [client_addr]" 