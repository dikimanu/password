from ml.model_loader import get_classifier
from ml.feature_engineering import features_to_vector, FEATURE_ORDER
import pandas as pd


def classify_attempt(features: dict):
    """Returns (predicted_label, confidence, probability_of_attack)."""
    classifier = get_classifier()
    vector = pd.DataFrame([features_to_vector(features)], columns=FEATURE_ORDER)

    predicted_label = classifier.predict(vector)[0]
    probabilities = classifier.predict_proba(vector)[0]
    classes = classifier.classes_

    prob_map = dict(zip(classes, probabilities))
    confidence = float(prob_map.get(predicted_label, 0.0))
    prob_of_attack = float(1.0 - prob_map.get("NORMAL", 0.0))

    return predicted_label, confidence, prob_of_attack
