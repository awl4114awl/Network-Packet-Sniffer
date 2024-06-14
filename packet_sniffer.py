from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(interface):
    print(f"Sniffing on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with the network interface you want to sniff on
    network_interface = 'eth0'
    start_sniffing(network_interface)
