import ipaddress
import statistics

#features to feed the model
model_features = [
    'dsport', 'proto','dur', 'sbytes', 'dbytes', 'Spkts', 'Dpkts',
    'smeansz', 'dmeansz', 'Sload', 'pkt_ratio', 'byte_ratio',
    'Sintpkt', 'Dintpkt', 'Sjit', 'Djit', 'tcprtt', 'is_sm_ips_ports',
    'src_is_private', 'dst_is_private', 'src_is_loopback', 'dst_is_loopback',
]


def extract_features(flow):
    def calc_mean(l):
        return sum(l) / len(l) if l else 0.0

    def calc_jitter(l):
        if len(l) < 2:
            return 0.0
        try:
            return statistics.stdev(l)
        except Exception:
            return 0.0

    try:
        dur = max(flow['last_seen_time'] - flow['start_time'], 1e-9)

        spkts = flow['packets_fwd']
        dpkts = flow['packets_bwd']
        sbytes = flow['bytes_fwd']
        dbytes = flow['bytes_bwd']

        #time from flow start to first backward packet
        tcprtt = 0.0
        if flow.get('first_bwd_time') is not None:
            tcprtt = max(flow['first_bwd_time'] - flow['start_time'], 0.0)

        pkt_ratio  = spkts  / (dpkts  + 1e-9)
        byte_ratio = sbytes / (dbytes + 1e-9)

        src_ip = flow['srcip']
        dst_ip = flow['dstip']

        try:
            src_is_private = int(ipaddress.ip_address(src_ip).is_private)
        except ValueError:
            src_is_private = 0
        try:
            dst_is_private = int(ipaddress.ip_address(dst_ip).is_private)
        except ValueError:
            dst_is_private = 0
        try:
            src_is_loopback = int(ipaddress.ip_address(src_ip).is_loopback)
        except ValueError:
            src_is_loopback = 0
        try:
            dst_is_loopback = int(ipaddress.ip_address(dst_ip).is_loopback)
        except ValueError:
            dst_is_loopback = 0

        return {
            'srcip':          src_ip,
            'dstip':          dst_ip,
            'sport':          flow['sport'],
            'dsport':         flow['dsport'],
            'proto':          flow['proto'],
            'dur':            dur,
            'Stime':          flow['start_time'],
            'Ltime':          flow['last_seen_time'],
            'Sintpkt':        calc_mean(flow['inter_arrival_fwd']),
            'Dintpkt':        calc_mean(flow['inter_arrival_bwd']),
            'Sjit':           calc_jitter(flow['inter_arrival_fwd']),
            'Djit':           calc_jitter(flow['inter_arrival_bwd']),
            'tcprtt':         tcprtt,
            'Spkts':          spkts,
            'Dpkts':          dpkts,
            'sbytes':         sbytes,
            'dbytes':         dbytes,
            'smeansz':        sbytes / spkts if spkts > 0 else 0.0,
            'dmeansz':        dbytes / dpkts if dpkts > 0 else 0.0,
            'Sload':          sbytes / dur,

            'is_sm_ips_ports': int(src_ip == dst_ip and flow['sport'] == flow['dsport']),

            #Derived features
            'pkt_ratio':       pkt_ratio,
            'byte_ratio':      byte_ratio,
            'src_is_private':  src_is_private,
            'dst_is_private':  dst_is_private,
            'src_is_loopback': src_is_loopback,
            'dst_is_loopback': dst_is_loopback,
        }

    except Exception as e:
        print(f"[!] Feature extraction error: {e}")
        return None

#returns a list of features to feed the model
def get_model_vector(features):
    if features is None:
        return None
    try:
        return [float(features[f]) for f in model_features]
    except KeyError as e:
        print(f"[!] Missing feature '{e}' when building model vector")
        return None