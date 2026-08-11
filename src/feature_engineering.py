import re
from pathlib import Path

import pandas as pd


LOG_FILE = Path("data/apache_logs.txt")
OUTPUT_FILE = Path("output/ip_features.csv")


LOG_PATTERN = re.compile(
    r'^(\S+) \S+ \S+ '
    r'\[([^\]]+)\] '
    r'"(\S+) (.*?) HTTP/[^"]+" '
    r'(\d{3}) (\S+) '
    r'"(.*?)" "(.*?)"$'
)


records = []

with LOG_FILE.open("r", encoding="utf-8", errors="replace") as file:
    for line in file:
        match = LOG_PATTERN.match(line.rstrip("\n"))

        if not match:
            continue

        (
            source_ip,
            timestamp,
            method,
            path,
            status,
            response_bytes,
            referrer,
            user_agent,
        ) = match.groups()

        records.append(
            {
                "source_ip": source_ip,
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "status": int(status),
                "response_bytes": response_bytes,
                "referrer": referrer,
                "user_agent": user_agent,
            }
        )


df = pd.DataFrame(records)

# HTTP error indicator
df["is_error"] = df["status"] >= 400

# Paths that may be useful for security investigation
suspicious_patterns = (
    r"admin|login|wp-admin|phpmyadmin|config|passwd|"
    r"etc/passwd|\.env|\.git|cmd|shell|cgi-bin"
)

df["is_suspicious_path"] = (
    df["path"]
    .str.lower()
    .str.contains(suspicious_patterns, regex=True, na=False)
)

# Aggregate behavior by source IP
ip_features = (
    df.groupby("source_ip")
    .agg(
        request_count=("source_ip", "size"),
        error_count=("is_error", "sum"),
        unique_paths=("path", "nunique"),
        suspicious_path_count=("is_suspicious_path", "sum"),
    )
    .reset_index()
)

# Derived behavioral features
ip_features["error_rate"] = (
    ip_features["error_count"] / ip_features["request_count"]
)

ip_features["scan_path_ratio"] = (
    ip_features["unique_paths"] / ip_features["request_count"]
)

# Make sure output directory exists
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

ip_features.to_csv(OUTPUT_FILE, index=False)

print("=" * 60)
print("FEATURE ENGINEERING RESULTS")
print("=" * 60)

print(f"HTTP events parsed: {len(df):,}")
print(f"Unique source IPs:  {len(ip_features):,}")
print(f"Output file:        {OUTPUT_FILE}")

print("\nFEATURES:")
print(ip_features.head(10).to_string(index=False))
