# Import necessary modules from Scapy for packet sniffing and analysis
from scapy.all import sniff, IP, TCP, UDP

# Define a callback function that will be called for each captured packet
def packet_callback(packet):
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        
        # Extract source and destination IP addresses from the IP layer
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Extract the protocol number
        proto = packet[IP].proto
        
        # Check if the packet is a TCP packet
        if packet.haslayer(TCP):
            
            # Mark the packet type as TCP
            p_type = "TCP"
            
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
        # Check if the packet is a UDP packet
        elif packet.haslayer(UDP):
            
            # Mark the packet type as UDP
            p_type = "UDP"
            
            # Extract source and destination ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        # If the packet is neither TCP nor UDP
        else:
            # Mark the packet type as Other
            p_type = "Other"
            # Set ports to None as they are not applicable
            src_port = None
            dst_port = None

        # Print the packet information
        print(f"Packet: {p_type} {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

# Define the main function to start packet capture
def main():
    
    # Print a message to indicate that packet capture has started
    print("Starting packet capture... Press Ctrl+C to stop.")
    
    # Start sniffing packets with Scapy's sniff function
    # The packet_callback function is passed as the callback to process each packet
    # store=0 tells Scapy not to keep packets in memory to save resources
    
    sniff(prn=packet_callback, store=0)

# Check if the script is being run directly (not imported as a module)
if __name__ == "__main__":
    
    # If so, call the main function to start the script
    main()