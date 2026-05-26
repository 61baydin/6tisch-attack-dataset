#!/bin/bash
# TUN arayüzünü temizleme ve düzeltme scripti

echo "=== TUN arayüzü temizleniyor ==="

# TUN arayüzünü kapat ve sil
sudo ifconfig tun0 down 2>/dev/null
sudo ip link delete tun0 2>/dev/null

# TUN modülünü yeniden yükle
sudo modprobe -r tun 2>/dev/null
sudo modprobe tun 2>&1

# TUN cihazının izinlerini kontrol et
if [ -c /dev/net/tun ]; then
    echo "✓ /dev/net/tun mevcut"
    ls -l /dev/net/tun
else
    echo "✗ /dev/net/tun bulunamadı!"
    exit 1
fi

# Çalışan tunslip6 süreçlerini sonlandır
pkill -f tunslip6 2>/dev/null
sleep 1

# Route temizliği
sudo ip route show | grep tun0 | while read route; do
    sudo ip route del $route 2>/dev/null
done

echo "=== Temizlik tamamlandı ==="
echo "Şimdi tunslip6'ı tekrar çalıştırabilirsiniz"

