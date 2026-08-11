from pathlib import Path

import pandas as pd


INPUT_FILE = Path("output/anomaly_results.csv")
OUTPUT_FILE = Path("output/security_alerts.csv")


df = pd.read_csv(INPUT_FILE)

# Only investigate IPs identified as anomalous by the ML model.
anomalies = df[df["classification"] == "Anomaly"].copy()


def generate_reasons(row):
    reasons = []

    # Strong behavioral indicators
    if row["request_count"] >= 100:
        reasons.append("High request volume")

    if row["error_rate"] >= 0.50 and row["request_count"] >= 10:
        reasons.append("High HTTP error rate")

    if row["unique_paths"] >= 50 and row["request_count"] >= 20:
        reasons.append("Large number of unique requested paths")

    if row["suspicious_path_count"] >= 3 and row["request_count"] >= 10:
        reasons.append("Multiple suspicious path patterns detected")

    if (
        row["scan_path_ratio"] >= 0.90
        and row["request_count"] >= 20
    ):
        reasons.append("High unique-path-to-request ratio")

    if not reasons:
        reasons.append(
            "Behavior differs significantly from peer source IPs"
        )

    return reasons


def determine_severity(row):
    score = 0

    # Volume
    if row["request_count"] >= 100:
        score += 2
    elif row["request_count"] >= 50:
        score += 1

    # Error behavior
    if row["error_rate"] >= 0.50 and row["request_count"] >= 10:
        score += 2
    elif row["error_rate"] >= 0.25 and row["request_count"] >= 10:
        score += 1

    # Path diversity
    if row["unique_paths"] >= 100 and row["request_count"] >= 50:
        score += 2
    elif row["unique_paths"] >= 50 and row["request_count"] >= 20:
        score += 1

    # Suspicious paths
    if row["suspicious_path_count"] >= 3 and row["request_count"] >= 10:
        score += 2
    elif row["suspicious_path_count"] >= 1 and row["request_count"] >= 10:
        score += 1

    # Scanning behavior
    if row["scan_path_ratio"] >= 0.90 and row["request_count"] >= 20:
        score += 1

    if score >= 5:
        return "High"

    if score >= 3:
        return "Medium"

    return "Low"


def map_mitre(row):
    mappings = []

    # Require meaningful request volume before calling this scanning.
    if (
        row["unique_paths"] >= 50
        and row["request_count"] >= 20
    ):
        mappings.append(
            "T1595 - Active Scanning"
        )

    # Do NOT automatically claim exploitation.
    # Suspicious paths alone are insufficient evidence of exploitation.
    if (
        row["suspicious_path_count"] >= 3
        and row["request_count"] >= 20
        and row["error_count"] >= 3
    ):
        mappings.append(
            "T1190 - Exploit Public-Facing Application (potential)"
        )

    if not mappings:
        mappings.append(
            "No direct MITRE technique assigned; analyst review required"
        )

    return "; ".join(mappings)


alerts = []

for _, row in anomalies.iterrows():

    reasons = generate_reasons(row)
    severity = determine_severity(row)
    mitre = map_mitre(row)

    if severity == "High":
        action = (
            "Prioritize investigation of source IP activity, requested "
            "paths, HTTP status patterns, and related events."
        )
    elif severity == "Medium":
        action = (
            "Review source IP behavior and investigate unusual request "
            "patterns and paths."
        )
    else:
        action = (
            "Review during normal SOC triage and correlate with related "
            "events before escalating."
        )

    alerts.append(
        {
            "source_ip": row["source_ip"],
            "risk_level": severity,
            "anomaly_score": round(row["anomaly_score"], 6),
            "request_count": row["request_count"],
            "error_count": row["error_count"],
            "unique_paths": row["unique_paths"],
            "suspicious_path_count": row["suspicious_path_count"],
            "error_rate": round(row["error_rate"], 4),
            "scan_path_ratio": round(row["scan_path_ratio"], 4),
            "reasons": "; ".join(reasons),
            "mitre_attack_mapping": mitre,
            "recommended_action": action,
        }
    )


alerts_df = pd.DataFrame(alerts)

severity_order = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
}

alerts_df["severity_order"] = alerts_df["risk_level"].map(
    severity_order
)

alerts_df = (
    alerts_df
    .sort_values(
        ["severity_order", "anomaly_score"]
    )
    .drop(columns=["severity_order"])
)

alerts_df.to_csv(OUTPUT_FILE, index=False)

print("=" * 60)
print("AUTOMATED SECURITY ALERT GENERATION")
print("=" * 60)

print(f"Anomalous IPs analyzed: {len(anomalies):,}")
print(f"Alerts generated:       {len(alerts_df):,}")

print("\nRisk distribution:")
print(alerts_df["risk_level"].value_counts())

print("\nTOP SECURITY FINDINGS")
print("=" * 60)

display_columns = [
    "source_ip",
    "risk_level",
    "request_count",
    "error_count",
    "unique_paths",
    "suspicious_path_count",
    "reasons",
    "mitre_attack_mapping",
]

print(
    alerts_df[display_columns]
    .head(20)
    .to_string(index=False)
)

print(f"\nSaved to: {OUTPUT_FILE}")
