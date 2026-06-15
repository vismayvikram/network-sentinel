# anomaly_detector.py
from logger import alert
import pickle
import os
from modules.ml_models import get_models
ml = get_models()

CLIP_BOUNDS = {}

try:
    module_dir = os.path.dirname(__file__)
    project_root = os.path.dirname(module_dir)
    bounds_path = os.path.join(project_root, 'ML', 'models', 'clip_bounds_mixed.pkl')
        
    with open(bounds_path, 'rb') as f:
        CLIP_BOUNDS = pickle.load(f)
except Exception as error:
    print(f"[!] Error loading clip bounds: {error}")

indices = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]

features = [
    'dsport', 'dur', 'sbytes', 'dbytes', 'Spkts', 'Dpkts',
    'smeansz', 'dmeansz', 'Sload', 'pkt_ratio', 'byte_ratio',
    'Sintpkt', 'Dintpkt', 'Sjit', 'Djit', 'tcprtt', 'is_sm_ips_ports',
    'src_is_private', 'dst_is_private', 'src_is_loopback', 'dst_is_loopback'
]

def detect(feature_vector, source_ip, dest_ip):

    try:
        anomaly_model = ml.get_anomaly_model()
        
        if not anomaly_model or not feature_vector:
            return False

        #Slice only anomaly model features
        sliced = [feature_vector[i] for i in indices]

        # Clip
        clipped_vector = []
        for i in range(len(sliced)):
            val = sliced[i]
            b = CLIP_BOUNDS.get(features[i])
            if b:
                val = max(min(val, b[1]), b[0])
            clipped_vector.append(val)

        prediction = anomaly_model.predict([clipped_vector])[0]
        
        score_min, score_max = -0.753, -0.316

        if prediction == -1:
            anomaly_score = anomaly_model.score_samples([clipped_vector])[0]
            anomaly_confidence = (anomaly_score - score_max) / (score_min - score_max) * 100
            confidence_pct = round(min(max(anomaly_confidence, 0), 100), 2)
            
            # Professional Threshold: Only alert if the deviation is significant (> 90%)
            if confidence_pct >= 90:
                alert("ANOMALY", source_ip, f"Anomalous traffic detected from {source_ip} to {dest_ip} with {confidence_pct}% confidence")
                return True
        else:
            return False
    
    except Exception as error:
        print(f"[!] Anomaly detection error: {error}")
        return False