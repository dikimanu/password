from ml.model_loader import get_anomaly_detector
from ml.feature_engineering import features_to_vector, FEATURE_ORDER
import pandas as pd


def anomaly_score(features: dict):
    """Returns True if the behavior is flagged as anomalous."""
    detector = get_anomaly_detector()
    vector = pd.DataFrame([features_to_vector(features)], columns=FEATURE_ORDER)
    prediction = detector.predict(vector)[0]  # 1 = normal, -1 = anomaly
    return prediction == -1
