import socket
import sys
from datetime import datetime

# --- Ayarlar ---
UDP_IP = '::'         # Tüm IPv6 adreslerinden dinle
UDP_PORT = 5678       # Dinlenecek UDP portu
# --- Bitiş ---

# Log dosyasını oluştur ve stdout'u yönlendir
# Optional argv[1] = explicit log filename (used by parallel workers to avoid
# timestamp collisions). Default: timestamp-based filename in cwd.
# Optional argv[2] = run metadata string (whitespace-separated key=val pairs,
# e.g. "attack=blackhole scale=21 placement=core atkcount=5 seed=42
# attackers=3,4,5,7,8"); written as a '# run_metadata: ...' header so the log
# is self-describing even if the file is later renamed or moved.
if len(sys.argv) > 1:
    log_filename = sys.argv[1]
else:
    log_filename = datetime.now().strftime('%Y-%m-%d_%H-%M-%S.log')
metadata = sys.argv[2] if len(sys.argv) > 2 else ''
log_file = open(log_filename, 'w')
original_stdout = sys.stdout
sys.stdout = log_file
if metadata:
    log_file.write(f"# run_metadata: {metadata}\n")
    log_file.write(f"# started: {datetime.now().isoformat(timespec='seconds')}\n")
    log_file.flush()

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