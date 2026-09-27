import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from config import Config
from ml.feature_engineering import FEATURE_ORDER
from ml.dataset_generator import generate_dataset


def train():
    if not os.path.exists(Config.DATASET_PATH):
        generate_dataset()

    df = pd.read_csv(Config.DATASET_PATH)
    X = df[FEATURE_ORDER]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    classifier.fit(X_train, y_train)

    preds = classifier.predict(X_test)
    print(classification_report(y_test, preds))

    # Anomaly detector trained only on NORMAL behavior
    normal_X = df[df["label"] == "NORMAL"][FEATURE_ORDER]
    anomaly_detector = IsolationForest(contamination=0.05, random_state=42)
    anomaly_detector.fit(normal_X)

    os.makedirs(Config.MODEL_DIR, exist_ok=True)
    joblib.dump(classifier, os.path.join(Config.MODEL_DIR, "attack_classifier.pkl"))
    joblib.dump(anomaly_detector, os.path.join(Config.MODEL_DIR, "anomaly_detector.pkl"))

    print(f"Models saved to: {Config.MODEL_DIR}")


if __name__ == "__main__":
    train()
