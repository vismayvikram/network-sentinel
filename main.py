import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNSQR

from modules.syn_flood import detect_syn_flood
from modules.icmp_abuse import detect_icmp_abuse
from modules.arp_spoof import detect_arp_spoofing
from modules.dns_tunnel import detect_dns_tunneling
from modules.port_scan import detect_port_scan
from modules.http_inspect import detect_http_inspection

interface = conf.iface
count = 0

def packet_process(packet):
    global count
    count+=1

    try:
        # ARP
        if packet.haslayer(ARP):
            detect_arp_spoofing(packet)
        
        if not packet.haslayer(IP):
            return
        
        # ICMP
        if packet.haslayer(ICMP):
            detect_icmp_abuse(packet)
        
        # TCP
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":
                detect_syn_flood(packet)
            
            detect_port_scan(packet)

            # HTTP Inspection
            if packet[TCP].dport in [80, 8080, 443]:
                detect_http_inspection(packet)

        #DNS
        if packet.haslayer("DNS"):
            detect_dns_tunneling(packet)
        
    except Exception as ex:
        print("[!] Error processing packet: ", ex)
                

def main_nids():
    print("[*] Starting NIDS on interface: ", interface)
    print("[*] Listening for packets...")
    print("[*] Press Ctrl+C to stop.")

    try:
        sniff(iface= interface, prn = packet_process, store = False)

    except PermissionError:
        print("[!] PERMISSION DENIED: This program requires root provileges to run.")
        print("    Please run the program with elevated permissions.")
    
    print("\n[*] Stopping NIDS...")
    print("[*] Total packets captured: ", count)
    print("[*] Exiting.")
    exit(0)
    
if __name__ == "__main__":
    main_nids()

