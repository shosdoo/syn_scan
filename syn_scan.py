from scapy.all import *
import threading
import sys
from datetime import datetime

# Función para escanear un puerto específico
def scan_port(target, port):
    try:
        syn_packet = IP(dst=target) / TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=1, verbose=False)
        if response:
            if response.haslayer(TCP):
                if response[TCP].flags == 'SA':  # SYN-ACK
                    print(f"Puerto {port} está abierto")                		#	 Enviar un paquete RST para restablecer la conexión
                    rst_packet = IP(dst=target) / TCP(dport=port, flags='R')
                    send(rst_packet, verbose=False)
    except KeyboardInterrupt:
        print('ol')
        exit(0)

def syn_scan(target, start_port, end_port, max_threads=100):
    try:
        print('-' * 50)
        print(f"Escaneando la ip: {target} \n\n" "Escaneo iniciado en: " + str(datetime.now()))
        print('-' * 50)

    # Lista para almacenar los hilos
        threads = []

        for port in range(start_port, end_port + 1):
        # Crear un hilo para cada puerto
            t = threading.Thread(target=scan_port, args=(target, port))
            threads.append(t)
            t.start()

        # Limitar el número de hilos en ejecución simultáneamente
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []

    # Esperar a que todos los hilos terminen
        for t in threads:
            t.join()
    except KeyboardInterrupt:
            print('Programa finalizado.')
            exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Uso: python3 syn_scan.py <target> <start_port> <end_port> <max_threads>")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    max_threads = int(sys.argv[4])

    syn_scan(target, start_port, end_port, max_threads)
