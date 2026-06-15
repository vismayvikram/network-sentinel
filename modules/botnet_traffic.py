from logger import alert
from modules.ml_models import get_models
ml = get_models()

indices = [0, 2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]

def detect_botnet_traffic(feature_vector, source_ip, dest_ip):
    try:
        botnet_model = ml.get_botnet_model()
        
        if not botnet_model or not feature_vector:
            return False

        #pass only botnet features to prediction model
        sliced = [feature_vector[i] for i in indices]

        prediction = botnet_model.predict([sliced])[0]
        confidence_scores = botnet_model.predict_proba([sliced])[0]
        
        botnet_confidence = confidence_scores[1]
        confidence_pct = round(botnet_confidence * 100, 2)
        
                               #to prevent fase positives
        if prediction == 1 and confidence_pct >= 90:
            alert("BOTNET", source_ip, f"Botnet traffic detected from {source_ip} to {dest_ip} with {confidence_pct}% confidence")
            return True
        else:
            return False
    
    except Exception as error:
        print(f"[!] Botnet detection error: {error}")
        return False