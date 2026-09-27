import csv
import random
import os

from config import Config

LABELS = ["NORMAL", "BRUTE_FORCE", "PASSWORD_SPRAY", "CREDENTIAL_STUFFING", "SUSPICIOUS"]


def generate_row(label):
    if label == "NORMAL":
        return {
            "attempts_in_window": random.randint(0, 2),
            "failed_in_window": random.randint(0, 1),
            "failed_ratio_recent": round(random.uniform(0.0, 0.2), 2),
            "new_device_flag": random.choice([0, 0, 0, 1]),
            "unusual_hour": random.choice([0, 0, 0, 1]),
            "label": label,
        }
    if label == "BRUTE_FORCE":
        return {
            "attempts_in_window": random.randint(8, 30),
            "failed_in_window": random.randint(7, 28),
            "failed_ratio_recent": round(random.uniform(0.7, 1.0), 2),
            "new_device_flag": random.choice([0, 1]),
            "unusual_hour": random.choice([0, 1]),
            "label": label,
        }
    if label == "PASSWORD_SPRAY":
        return {
            "attempts_in_window": random.randint(3, 8),
            "failed_in_window": random.randint(3, 7),
            "failed_ratio_recent": round(random.uniform(0.5, 0.9), 2),
            "new_device_flag": 1,
            "unusual_hour": random.choice([0, 1]),
            "label": label,
        }
    if label == "CREDENTIAL_STUFFING":
        return {
            "attempts_in_window": random.randint(5, 15),
            "failed_in_window": random.randint(2, 8),
            "failed_ratio_recent": round(random.uniform(0.3, 0.7), 2),
            "new_device_flag": 1,
            "unusual_hour": random.choice([0, 1]),
            "label": label,
        }
    # SUSPICIOUS - ambiguous, low-moderate signals
    return {
        "attempts_in_window": random.randint(1, 4),
        "failed_in_window": random.randint(0, 2),
        "failed_ratio_recent": round(random.uniform(0.1, 0.4), 2),
        "new_device_flag": 1,
        "unusual_hour": 1,
        "label": label,
    }


def generate_dataset(rows_per_label=400):
    os.makedirs(os.path.dirname(Config.DATASET_PATH), exist_ok=True)
    fieldnames = ["attempts_in_window", "failed_in_window", "failed_ratio_recent",
                  "new_device_flag", "unusual_hour", "label"]

    with open(Config.DATASET_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for label in LABELS:
            for _ in range(rows_per_label):
                writer.writerow(generate_row(label))

    print(f"Synthetic dataset written to: {Config.DATASET_PATH}")


if __name__ == "__main__":
    generate_dataset()
