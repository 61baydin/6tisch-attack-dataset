import socket
import sys
from datetime import datetime

# --- Ayarlar ---
UDP_IP = '::'         # Tüm IPv6 adreslerinden dinle
UDP_PORT = 5678       # Dinlenecek UDP portu
# --- Bitiş ---

# Log dosyasını oluştur ve stdout'u yönlendir
log_filename = datetime.now().strftime('%Y-%m-%d_%H-%M-%S.log')
log_file = open(log_filename, 'w')
original_stdout = sys.stdout
sys.stdout = log_file

def print_and_log(message):
    """Hem orijinal konsola hem de log dosyasına yazar."""
    print(message)                  # Bu, dosyaya yazar
    original_stdout.write(message + '\n') # Bu, konsola yazar
    log_file.flush()                      # Dosyaya hemen yazılmasını garantiler

# Soketi oluştur
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print_and_log(f"Logging to: {log_filename}")
print_and_log(f"Listening on UDP port {UDP_PORT} (IPv6)...")

try:
    while True:
        data, addr = sock.recvfrom(1024)
        # Gelen veriyi ve adresi formatla
        log_message = f"Received from {addr}: {data}"
        print_and_log(log_message)
except KeyboardInterrupt:
    print_and_log("\nListener stopped by user.")
finally:
    # Betik durduğunda dosyayı kapat
    log_file.close()
    sys.stdout = original_stdout # stdout'u eski haline getir
    sock.close() 