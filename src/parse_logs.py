import re
from pathlib import Path

LOG_FILE = Path("data/apache_logs.txt")

# Apache Combined Log Format
LOG_PATTERN = re.compile(
    r'^(\S+) \S+ \S+ '
    r'\[([^\]]+)\] '
    r'"(\S+) (.*?) HTTP/[^"]+" '
    r'(\d{3}) (\S+) '
    r'"(.*?)" "(.*?)"$'
)

parsed = []
failed = []

with LOG_FILE.open("r", encoding="utf-8", errors="replace") as file:
    for line_number, line in enumerate(file, start=1):
        line = line.rstrip("\n")

        match = LOG_PATTERN.match(line)

        if match:
            source_ip, timestamp, method, path, status, response_bytes, referrer, user_agent = match.groups()

            parsed.append({
                "source_ip": source_ip,
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "status": int(status),
                "response_bytes": response_bytes,
                "referrer": referrer,
                "user_agent": user_agent,
            })
        else:
            failed.append((line_number, line))

print("=" * 60)
print("APACHE LOG PARSING RESULTS")
print("=" * 60)

print(f"Total lines:       {len(parsed) + len(failed):,}")
print(f"Parsed successfully: {len(parsed):,}")
print(f"Failed to parse:    {len(failed):,}")

print("\nFIRST 3 PARSED RECORDS")
print("=" * 60)

for record in parsed[:3]:
    print(record)

if failed:
    print("\nFIRST FAILED RECORD")
    print("=" * 60)
    print(f"Line number: {failed[0][0]}")
    print(failed[0][1])
