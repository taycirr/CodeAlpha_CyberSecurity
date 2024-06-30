from scapy.all import *

def packet_callback(packet):
    # Print the packet summary
    print(packet.summary())

def main():
    print("Starting network sniffer...")
    # Sniff indefinitely and call packet_callback for each captured packet
    sniff(prn=packet_callback)

if __name__ == "__main__":
    main()
