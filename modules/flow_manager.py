import time
from scapy.layers.inet import IP, TCP, UDP

active_flows = {}


# Create/update flow for packet
def add_packet_to_flow(packet):
    try:
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        proto = ip.proto
        sport = dsport = 0

        if packet.haslayer(TCP):
            sport, dsport = packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            sport, dsport = packet[UDP].sport, packet[UDP].dport

        # Creating a unique flow identifier and checking for bidirection movement
        five_tuple = (ip.src, ip.dst, sport, dsport, proto)
        reverse_tuple = (ip.dst, ip.src, dsport, sport, proto)

        if five_tuple in active_flows:
            return active_flows[five_tuple]
        if reverse_tuple in active_flows:
            return active_flows[reverse_tuple]

        now = time.time()
        active_flows[five_tuple] = {
            'srcip':five_tuple[0],
            'dstip':five_tuple[1],
            'sport':five_tuple[2],
            'dsport':five_tuple[3],
            'proto':five_tuple[4],
            'start_time':now,
            'last_seen_time':now,
            'packets_fwd':0,
            'packets_bwd':0,
            'bytes_fwd':0,
            'bytes_bwd':0,
            'inter_arrival_fwd':[],
            'inter_arrival_bwd':[],
            'last_pkt_time_fwd':None,
            'last_pkt_time_bwd':None,
            'first_bwd_time':None,
            'tcp_flags':set(),
        }

        return active_flows[five_tuple]
    except Exception as e:
        print(f"[!] Error adding packet to flow: {e}")
        return None



#Update packet info
def update_flow_stats(packet, flow):
    if not flow or not packet.haslayer(IP):
        return
    
    try:
        now = time.time()
        ip = packet[IP]
        pkt_len = len(packet)
        is_forward = (ip.src == flow['srcip'])
        
        if is_forward:
            if flow['last_pkt_time_fwd']:
                flow['inter_arrival_fwd'].append(now - flow['last_pkt_time_fwd'])

            flow['last_pkt_time_fwd']= now
            flow['packets_fwd']+= 1
            flow['bytes_fwd']+= pkt_len
        else:
            if not flow['first_bwd_time']:
                flow['first_bwd_time']= now

            if flow['last_pkt_time_bwd']:
                flow['inter_arrival_bwd'].append(now - flow['last_pkt_time_bwd'])

            flow['last_pkt_time_bwd']= now
            flow['packets_bwd']+= 1
            flow['bytes_bwd']+= pkt_len
        
        if packet.haslayer(TCP):
            flags = str(packet[TCP].flags)
            if 'F' in flags:
                flow['tcp_flags'].add('F')
            if 'R' in flags:
                flow['tcp_flags'].add('R')
        
        flow['last_seen_time'] = now
    except Exception as e:
        print(f"[!] Error updating flow stats: {e}")



#CHecks if flow timeout is is happening and returns flow
def check_flow_timeout(current_time):
    completed = []
    
    try:
        for flow_key, flow in list(active_flows.items()):
            proto = flow['proto']
            if proto == 6:
                idle_timeout = 30 #TCP flow idle timeout
            else:
                idle_timeout = 20 #other flow idle timeout

            time_inactive = current_time - flow['last_seen_time']
            flow_age = current_time - flow['start_time']
            
            fin_rst = 'F' in flow['tcp_flags'] or 'R' in flow['tcp_flags']
            tcp_closed = (proto == 6) and fin_rst
            
            if tcp_closed or time_inactive > idle_timeout or flow_age > 120: #Max flow time = 2 mins
                completed.append(flow)
                del active_flows[flow_key]
    except Exception as e:
        print(f"[!] Error checking flow timeout: {e}")
    
    return completed