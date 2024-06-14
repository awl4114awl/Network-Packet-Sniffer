# Python Network Packet Sniffer

A Python-based network packet sniffer using Scapy, capable of capturing and analyzing network traffic on a specified interface. Includes a basic version for general packet capturing and an enhanced version with TCP packet filtering and logging capabilities. Ideal for learning and exploring network traffic analysis and cybersecurity concepts.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Basic Script](#basic-script)
  - [Overview](#overview)
  - [Full Code](#full-code)
  - [Explanation](#explanation)
  - [Running the Script](#running-the-script)
- [Enhanced Script](#enhanced-script)
  - [Full Code](#full-code-1)
  - [Running the Script](#running-the-script-1)
- [Enhancing the Packet Sniffer](#enhancing-the-packet-sniffer)
- [Contributions](#contributions)
- [License](#license)
- [Contact](#contact)

## Features

- **Basic Packet Sniffer**:
  - Captures all packets on a specified network interface.
  - Prints a summary of each captured packet.

- **Enhanced Packet Sniffer**:
  - Filters for TCP packets.
  - Logs captured packets to a file.

## Prerequisites

- Python 3.x
- Scapy library

## Installation

1. **Install Scapy**:
    ```bash
    pip install scapy
    ```

## Getting Started

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/python-packet-sniffer.git
    cd python-packet-sniffer
    ```

2. **Run the basic packet sniffer**:
    ```bash
    sudo python packet_sniffer.py
    ```

3. **Run the enhanced packet sniffer**:
    ```bash
    sudo python enhanced_packet_sniffer.py
    ```

## Basic Script

### Overview

A network packet sniffer is a tool that captures and analyzes network traffic. Below is a basic example of a Python-based network packet sniffer using the `scapy` library.

### Full Code

```python
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
```

### Explanation

1. **Import Scapy**:
    - `from scapy.all import sniff`: Imports the `sniff` function from Scapy to capture packets.

2. **Define Packet Callback**:
    - `def packet_callback(packet)`: A callback function that is called for each captured packet. It prints a summary of the packet.

3. **Start Sniffing**:
    - `def start_sniffing(interface)`: A function that starts the packet sniffing on the specified network interface.
    - `sniff(iface=interface, prn=packet_callback, store=0)`: The `sniff` function captures packets on the given interface, calls `packet_callback` for each packet, and does not store the packets in memory.

4. **Main Block**:
    - `network_interface = 'eth0'`: Replace `'eth0'` with the appropriate network interface on your system.
    - `start_sniffing(network_interface)`: Starts the packet sniffing on the specified interface.

### Running the Script

Run the script with appropriate permissions (you may need to run it as root/admin depending on your system):

```bash
sudo python packet_sniffer.py
```

## Enhanced Script

### Full Code

```python
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
```

### Running the Script

Run the enhanced script with appropriate permissions:

```bash
sudo python enhanced_packet_sniffer.py
```

## Enhancing the Packet Sniffer

Here are some ways to enhance this basic packet sniffer:

1. **Filter Packets**:
    - Capture only specific types of packets (e.g., TCP, UDP, HTTP).
    - Use Scapy's filter syntax to specify the types of packets to capture.

2. **Packet Analysis**:
    - Extract and display specific fields from captured packets (e.g., source IP, destination IP, port numbers).
    - Save captured packets to a file for later analysis.

3. **Logging**:
    - Log captured packets to a file instead of printing to the console.

4. **GUI**:
    - Create a graphical user interface for the packet sniffer using libraries like Tkinter or PyQt.

## Contributions

Contributions are welcome! Feel free to open an issue or submit a pull request with any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or feedback, please contact [jordanryancalvert@gmail.com](mailto:jordanryancalvert@gmail.com).
```

Feel free to adjust the scripts and README to fit your project requirements and preferences.
