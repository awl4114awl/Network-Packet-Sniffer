from scapy.all import sniff
import logging

# Set up logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    if packet.haslayer('TCP'):
        log_message = f"TCP Packet: {packet[0][1].src} -> {packet[0][1].dst} (port {packet[0][2].sport} -> {packet[0][2].dport})"
        print(log_message)
        logging.info(log_message)

def start_sniffing(interface):
    print(f"Sniffing on interface {interface}")
    sniff(iface=interface, filter='tcp', prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with the network interface you want to sniff on
    network_interface = 'eth0'
    start_sniffing(network_interface)
