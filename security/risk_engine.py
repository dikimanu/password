from security.behavior_analysis import build_features
from ml.attack_classifier import classify_attempt
from ml.anomaly_detection import anomaly_score
from config import Config


def assess_risk(user_id, identifier, ip_address, user_agent):
    features = build_features(user_id, identifier, ip_address, user_agent)

    predicted_label, confidence, prob_of_attack = classify_attempt(features)
    is_anomalous = anomaly_score(features)

    risk_score = prob_of_attack
    if is_anomalous:
        risk_score = min(1.0, risk_score + 0.15)

    if risk_score <= Config.RISK_LOW_MAX:
        risk_level = "LOW"
    elif risk_score <= Config.RISK_MEDIUM_MAX:
        risk_level = "MEDIUM"
    elif risk_score <= Config.RISK_HIGH_MAX:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "risk_score": round(risk_score, 3),
        "risk_level": risk_level,
        "attack_category": predicted_label,
        "confidence": round(confidence, 3),
        "is_anomalous": is_anomalous,
        "features": features,
    }
