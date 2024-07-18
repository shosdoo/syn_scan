from scapy.all import *
import threading
import sys
from datetime import datetime

def scan_port(target, port):
    syn_packet = IP(dst=target) / TCP(dport=port, flags='S')
    response = sr1(syn_packet, timeout=1, verbose=False)

    if response:
        if response.haslayer(TCP):
            if response[TCP].flags == 'SA':  # SYN-ACK
                print(f"Puerto {port} está abierto")
                rst_packet = IP(dst=target) / TCP(dport=port, flags='R')
                send(rst_packet, verbose=False)
            elif response[TCP].flags == 'RA':  # RST-ACK
                print(f"Puerto {port} está cerrado")
                

def syn_scan(target, start_port, end_port, max_threads=100):
    print('-' * 50)
    print(f"Escaneando la ip: {target} \n\n" "Escaneo iniciado en: " + str(datetime.now()))
    print('-' * 50)

    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Uso: python3 syn_scan.py <target> <start_port> <end_port> <max_threads>")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    max_threads = int(sys.argv[4])

    syn_scan(target, start_port, end_port, max_threads)
