# beaconing_detector.py
from logger import alert
from modules.ml_models import get_models
ml = get_models()

indices = [0, 1, 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]

def detect_beaconing(feature_vector, source_ip, dest_ip):
    try:
        beaconing_model = ml.get_beaconing_model()
        
        if not beaconing_model or not feature_vector:
            return False

        #pass only beaconing features to prediction model
        sliced = [feature_vector[i] for i in indices]

        prediction = beaconing_model.predict([sliced])[0]
        confidence_scores = beaconing_model.predict_proba([sliced])[0]
        
        beacon_confidence = confidence_scores[1]
        confidence_pct = round(beacon_confidence * 100, 2)
        
        if prediction == 1 and confidence_pct >= 90:
            alert("BEACONING", source_ip, f"Beaconing detected from {source_ip} to {dest_ip} with {confidence_pct}% confidence")
            return True
        else:
            return False
    
    except Exception as error:
        print(f"[!] Beaconing detection error: {error}")
        return False