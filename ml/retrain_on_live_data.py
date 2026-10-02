import os
import json
import shutil
import pandas as pd

from config import Config
from database.database import get_connection
from ml.feature_engineering import FEATURE_ORDER
from ml.train_model import train


def fetch_real_rows():
    """Pulls login attempts that have both a feature vector and a known
    attack category — the only rows usable as labeled training data."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT features_json, attack_category
        FROM login_attempts
        WHERE features_json IS NOT NULL AND attack_category IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()

    records = []
    for row in rows:
        try:
            features = json.loads(row["features_json"])
            record = {key: features[key] for key in FEATURE_ORDER}
            record["label"] = row["attack_category"]
            records.append(record)
        except (KeyError, json.JSONDecodeError):
            continue  # skip malformed/incomplete rows rather than fail the whole run
    return records


def backup_existing_models():
    backup_dir = os.path.join(Config.MODEL_DIR, "backup")
    os.makedirs(backup_dir, exist_ok=True)
    for name in ("attack_classifier.pkl", "anomaly_detector.pkl"):
        src = os.path.join(Config.MODEL_DIR, name)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(backup_dir, name))
    print(f"Existing models backed up to: {backup_dir}")


def retrain_with_live_data():
    real_records = fetch_real_rows()
    print(f"Found {len(real_records)} usable real login attempts to add.")

    if not os.path.exists(Config.DATASET_PATH):
        print("No synthetic dataset found — run ml/train_model.py first to generate one.")
        return

    synthetic_df = pd.read_csv(Config.DATASET_PATH)

    if real_records:
        real_df = pd.DataFrame(real_records)
        combined_df = pd.concat([synthetic_df, real_df], ignore_index=True)
    else:
        print("No real data available yet — training on synthetic data only.")
        combined_df = synthetic_df

    combined_path = os.path.join(os.path.dirname(Config.DATASET_PATH), "authentication_logs_combined.csv")
    combined_df.to_csv(combined_path, index=False)
    print(f"Combined dataset saved to: {combined_path} ({len(combined_df)} total rows)")

    backup_existing_models()

    # Temporarily point training at the combined dataset
    original_path = Config.DATASET_PATH
    Config.DATASET_PATH = combined_path
    try:
        train()
    finally:
        Config.DATASET_PATH = original_path

    print("Retraining complete. Models updated in:", Config.MODEL_DIR)
    print("If the new models perform worse, restore from:", os.path.join(Config.MODEL_DIR, "backup"))


if __name__ == "__main__":
    retrain_with_live_data()