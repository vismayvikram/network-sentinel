import os
import pickle
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*joblib workers.*")
warnings.filterwarnings("ignore", message=".*feature names.*")

class MLModels:
    def __init__(self):
        self.botnet_model = None
        self.beaconing_model = None
        self.anomaly_model = None
        self.botnet_scaler = None
        self.beaconing_scaler = None

    def load_models(self):
        module_dir = os.path.dirname(__file__)
        project_root = os.path.dirname(module_dir)
        botnet_path = os.path.join(project_root, 'ML', 'models', 'botnet_rf_model.pkl')
        beaconing_path = os.path.join(project_root, 'ML', 'models', 'beacon_rf_model.pkl')
        anomaly_path = os.path.join(project_root, 'ML', 'models', 'anomaly_if_model.pkl')

        try:
            with open(botnet_path, 'rb') as f:
                self.botnet_model = pickle.load(f)
                if hasattr(self.botnet_model, 'n_jobs'):
                    self.botnet_model.n_jobs = 1
        except Exception as e:
            print(f"[!] Error loading botnet model: {e}")

        try:
            with open(beaconing_path, 'rb') as f:
                self.beaconing_model = pickle.load(f)
                if hasattr(self.beaconing_model, 'n_jobs'):
                    self.beaconing_model.n_jobs = 1
        except Exception as e:
            print(f"[!] Error loading beaconing model: {e}")

        try:
            with open(anomaly_path, 'rb') as f:
                self.anomaly_model = pickle.load(f)
                if hasattr(self.anomaly_model, 'n_jobs'):
                    self.anomaly_model.n_jobs = 1
        except Exception as e:
            print(f"[!] Error loading anomaly model: {e}")

    def get_botnet_model(self):
        return self.botnet_model
    
    def get_beaconing_model(self):
        return self.beaconing_model
    
    def get_anomaly_model(self):
        return self.anomaly_model
    
ml = MLModels()
ml.load_models()

def get_models():
    return ml