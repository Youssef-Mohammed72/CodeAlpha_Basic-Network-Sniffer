# Import necessary libraries
import json                 # For handling JSON data, not used in this script.
from scapy.all import *     # Import everything from Scapy for packet processing.
import sys                  # Access system-specific parameters and functions.

# Define a function to handle each packet captured.
def handle_packet(packet, log):     # This function takes a packet and a log file object as input.
    packet_info = {}        # Initialize an empty dictionary to hold packet information.
    
    # Check if the packet contains a TCP layer.
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)        # Extract the TCP layer from the packet.
        if tcp_layer:
            # Initialize packet_info with TCP details.
            packet_info = {
                "protocol": "TCP",
                "src_ip": "",
                "dst_ip": "",
                "src_port": tcp_layer.sport,
                "dst_port": tcp_layer.dport
            }
            
            # Safely attempt to extract IP layer details.
            ip_layer = packet.getlayer(IP)
            if ip_layer:
                packet_info["src_ip"] = ip_layer.src
                packet_info["dst_ip"] = ip_layer.dst
                
                # Process HTTP, HTTPS, FTP-data, FTP, SSH-SCP, Telnet, SMTP, POP3, NetBIOS-ns, NetBIOS-ssn, IMAP4, SMTPS, MySQL, PostgreSQL and HTTP Proxy traffic specifically.
                if tcp_layer.dport == 80:
                    packet_info["protocol"] += " (HTTP)"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load.decode(errors='ignore')
                        if "HTTP" in payload:
                            packet_info["payload"] = payload  # Capture the payload for HTTP
                            output = (
                                f'protocol: {packet_info.get("protocol", "")}\n'
                                f'src_ip: {packet_info.get("src_ip", "")}\n'
                                f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                                f'src_port: {packet_info.get("src_port", "")}\n'
                                f'dst_port: {packet_info.get("dst_port", "")}\n'
                                f'payload: {packet_info.get("payload", "")}\n\n'
                            )
                            log.write(output)
                            
                elif tcp_layer.dport == 443:
                    packet_info["protocol"] += " (HTTPS)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)

                elif tcp_layer.dport == 20:
                    packet_info["protocol"] += " (FTP-data)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 21:
                    packet_info["protocol"] += " (FTP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 22:
                    packet_info["protocol"] += " (SSH-SCP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 23:
                    packet_info["protocol"] += " (Telnet)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 25:
                    packet_info["protocol"] += " (SMTP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif tcp_layer.dport == 110:
                    packet_info["protocol"] += " (POP3)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 137:
                    packet_info["protocol"] += " (NetBIOS-ns)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 139:
                    packet_info["protocol"] += " (NetBIOS-ssn)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 143:
                    packet_info["protocol"] += " (IMAP4)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 465:
                    packet_info["protocol"] += " (SMTPS)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 3306:
                    packet_info["protocol"] += " (MySQL)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 5432:
                    packet_info["protocol"] += " (PostgreSQL)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif tcp_layer.dport == 8080:
                    packet_info["protocol"] += " (HTTP Proxy)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                else:
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)                     
            else:
                log.write("Packet does not contain an IP layer.\n\n")
                return  # Exit early if no relevant data can be extracted

    # Similar processing for UDP packets
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        if udp_layer:
            packet_info = {
                "protocol": "UDP",
                "src_ip": "",
                "dst_ip": "",
                "src_port": udp_layer.sport,
                "dst_port": udp_layer.dport
            }
            
            # Safely access IP layer assuming UDP layer exists
            ip_layer = packet.getlayer(IP)
            if ip_layer:
                packet_info["src_ip"] = ip_layer.src
                packet_info["dst_ip"] = ip_layer.dst
                
                # Process DNS, DHCP, TFTP, SNMP, NTP, Syslog, Portmapper/RPC, NetBIOS, mDNS, and general cases.
                if udp_layer.dport == 53:
                    dns_query = ""
                    if packet.haslayer(DNS):
                        dns_query = packet[DNS].qd.qname.decode(errors='ignore')
                        packet_info["dns_query"] = dns_query
                        packet_info["protocol"] += " (DNS Query)"
                        output = (
                            f'protocol: {packet_info.get("protocol", "")}\n'
                            f'src_ip: {packet_info.get("src_ip", "")}\n'
                            f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                            f'src_port: {packet_info.get("src_port", "")}\n'
                            f'dst_port: {packet_info.get("dst_port", "")}\n'
                            f'DNS Query: {packet_info.get("dns_query", "")}\n\n'
                        )
                        log.write(output)
                        
                    else:
                        packet_info["protocol"] += " (Potential DNS Query)"
                        output = (
                            f'protocol: {packet_info.get("protocol", "")}\n'
                            f'src_ip: {packet_info.get("src_ip", "")}\n'
                            f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                            f'src_port: {packet_info.get("src_port", "")}\n'
                            f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                        )
                        log.write(output)
                    
                elif udp_layer.dport == 67:
                    packet_info["protocol"] += " (DHCP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif udp_layer.dport == 68:
                    packet_info["protocol"] += " (DHCP client)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                elif udp_layer.dport == 69:
                    packet_info["protocol"] += " (TFTP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 161:
                    packet_info["protocol"] += " (SNMP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 162:
                    packet_info["protocol"] += " (SNMP Traps)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 123:
                    packet_info["protocol"] += " (NTP)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 514:
                    packet_info["protocol"] += " (Syslog)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 111:
                    packet_info["protocol"] += " (Portmapper/RPC)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 137:
                    packet_info["protocol"] += " (NetBIOS Name Service)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 138:
                    packet_info["protocol"] += " (NetBIOS Datagram Service)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 139:
                    packet_info["protocol"] += " (NetBIOS Session Service)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 445:
                    packet_info["protocol"] += " (Microsoft-DS)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
                elif udp_layer.dport == 5353 :
                    packet_info["protocol"] += " (mDNS)"
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                    
                else:
                    output = (
                        f'protocol: {packet_info.get("protocol", "")}\n'
                        f'src_ip: {packet_info.get("src_ip", "")}\n'
                        f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                        f'src_port: {packet_info.get("src_port", "")}\n'
                        f'dst_port: {packet_info.get("dst_port", "")}\n\n'
                    )
                    log.write(output)
                
            else:
                log.write("Packet does not contain an IP layer.\n\n")
                return  # Exit early if no relevant data can be extracted
        else:
            log.write("Packet does not contain a UDP layer.\n\n")
            return
     
    # Process ICMP packets.
    elif packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
        if icmp_layer:
            packet_info = {
                "protocol": "ICMP",
                "src_ip": packet.getlayer(IP).src,
                "dst_ip": packet.getlayer(IP).dst,
                "icmp_type": icmp_layer.type,
                "icmp_code": icmp_layer.code
            }
            output = (
                f'protocol: {packet_info.get("protocol", "")}\n'
                f'src_ip: {packet_info.get("src_ip", "")}\n'
                f'dst_ip: {packet_info.get("dst_ip", "")}\n'
                f'icmp_type: {packet_info.get("icmp_type", "")}\n'
                f'icmp_code: {packet_info.get("icmp_code", "")}\n\n'
            )
            log.write(output)   

# Define the main function to start packet sniffing.
def main(interface, filter=None, verbose=False):
    logfile_name = f"sniffer_{interface}_log.txt"
    with open(logfile_name, 'w') as logfile:
        try:
            sniff(iface=interface, filter=filter, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
            
            # Handle verbosity separately, perhaps by printing additional information
            if verbose:
                print("Verbose mode enabled. Additional information will be printed.")
                
        except KeyboardInterrupt:
            sys.exit(0)

# Execute the main function if the script is run directly.
if __name__ == "__main__":
    # Usage: python sniffer.py <interface> [filter] [verbose]
    
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 2 or len(sys.argv) > 5:
        print("Usage: python sniffer.py <interface> [filter] [verbose]")
        sys.exit(1)
    elif len(sys.argv) == 4:
        filter = sys.argv[2]
        verbose = sys.argv[3].lower() == "verbose"
    elif len(sys.argv) == 3:
        filter = sys.argv[2]
        verbose = False
    else:
        filter = None
        verbose = False
    main(sys.argv[1], filter, verbose)
