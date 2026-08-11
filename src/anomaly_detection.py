from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


INPUT_FILE = Path("output/ip_features.csv")
OUTPUT_FILE = Path("output/anomaly_results.csv")


df = pd.read_csv(INPUT_FILE)

# Numerical behavioral features used by the model
FEATURE_COLUMNS = [
    "request_count",
    "error_count",
    "unique_paths",
    "suspicious_path_count",
    "error_rate",
    "scan_path_ratio",
]

X = df[FEATURE_COLUMNS]

# Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
)

model.fit(X)

# Prediction:
#  1  = normal
# -1  = anomaly
df["anomaly_label"] = model.predict(X)

# Decision score:
# Lower values generally indicate more anomalous observations.
df["anomaly_score"] = model.decision_function(X)

# Convert model output into a more readable label
df["classification"] = df["anomaly_label"].map(
    {
        1: "Normal",
        -1: "Anomaly",
    }
)

# Sort most anomalous IPs first
results = df.sort_values("anomaly_score")

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
results.to_csv(OUTPUT_FILE, index=False)

print("=" * 60)
print("ISOLATION FOREST ANOMALY DETECTION")
print("=" * 60)

print(f"Source IPs analyzed: {len(df):,}")
print(f"Features used:       {len(FEATURE_COLUMNS)}")
print(f"Model:               Isolation Forest")
print(f"Trees:               200")

print("\nClassification:")
print(results["classification"].value_counts())

print("\nMOST ANOMALOUS SOURCE IPS")
print("=" * 60)

columns_to_show = [
    "source_ip",
    "request_count",
    "error_count",
    "unique_paths",
    "suspicious_path_count",
    "error_rate",
    "scan_path_ratio",
    "anomaly_score",
    "classification",
]

print(results[columns_to_show].head(20).to_string(index=False))

print(f"\nResults saved to: {OUTPUT_FILE}")
