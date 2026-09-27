import os
import joblib
from config import Config

_classifier = None
_anomaly_detector = None


def _paths():
    return (
        os.path.join(Config.MODEL_DIR, "attack_classifier.pkl"),
        os.path.join(Config.MODEL_DIR, "anomaly_detector.pkl"),
    )


def load_models():
    global _classifier, _anomaly_detector
    clf_path, anomaly_path = _paths()

    if not (os.path.exists(clf_path) and os.path.exists(anomaly_path)):
        from ml.train_model import train
        train()

    _classifier = joblib.load(clf_path)
    _anomaly_detector = joblib.load(anomaly_path)
    return _classifier, _anomaly_detector


def get_classifier():
    if _classifier is None:
        load_models()
    return _classifier


def get_anomaly_detector():
    if _anomaly_detector is None:
        load_models()
    return _anomaly_detector
