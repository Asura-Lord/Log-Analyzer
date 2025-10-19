# main.py
import os
import re
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# -------------------- Helper Functions --------------------

def parse_log(file_path):
    """Parse log file and return list of failed login entries"""
    if not os.path.exists(file_path):
        print("❌ Log file not found. Please check the path.")
        return []

    failed_entries = []
    with open(file_path, 'r') as f:
        for line in f:
            if "Failed password" in line:
                # Example line: Oct 19 10:41:23 ubuntu sshd[1245]: Failed password for root from 192.168.1.15 port 45432 ssh2
                timestamp_match = re.search(r'^\w+\s+\d+\s+\d+:\d+:\d+', line)
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                user_match = re.search(r'for (\w+)', line)
                if timestamp_match and ip_match:
                    failed_entries.append({
                        "timestamp": timestamp_match.group(),
                        "ip": ip_match.group(1),
                        "user": user_match.group(1) if user_match else "unknown"
                    })
    return failed_entries

def save_csv(df, name_prefix="suspicious_summary"):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"output/{name_prefix}_{timestamp}.csv"
    df.to_csv(path, index=False)
    print(f"✅ CSV report saved: {path}")
    return path

def plot_top_attackers(failed_entries):
    ip_counts = Counter([entry['ip'] for entry in failed_entries])
    df = pd.DataFrame(ip_counts.items(), columns=['IP', 'Failed Attempts']).sort_values('Failed Attempts', ascending=False)

    plt.figure(figsize=(8,5))
    plt.bar(df['IP'], df['Failed Attempts'], color='red')
    plt.title('Top IPs by Failed Login Attempts')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Failed Attempts')
    plt.tight_layout()
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"output/top_attackers_{timestamp}.png"
    plt.savefig(path)
    plt.show()
    print(f"✅ Top attackers chart saved: {path}")

def plot_attempts_over_time(failed_entries):
    df = pd.DataFrame(failed_entries)
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S')
    df_count = df.groupby(df['timestamp'].dt.strftime('%H:%M')).count()['ip']

    plt.figure(figsize=(10,4))
    plt.plot(df_count.index, df_count.values, marker='o', color='blue')
    plt.title('Failed Login Attempts Over Time')
    plt.xlabel('Time (HH:MM)')
    plt.ylabel('Number of Failed Attempts')
    plt.grid(True)
    plt.tight_layout()
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"output/failed_over_time_{timestamp}.png"
    plt.savefig(path)
    plt.show()
    print(f"✅ Failed attempts over time chart saved: {path}")

# -------------------- Main CLI --------------------

def main():
    print("=== Log Analyzer for Suspicious Activity v2.0 ===")
    log_file = input("Enter path to log file (e.g., auth.log or sample_log.txt): ")
    threshold = input("Enter threshold for suspicious IPs [default=5]: ")
    threshold = int(threshold) if threshold.isdigit() else 5

    entries = parse_log(log_file)
    if not entries:
        return

    ip_counts = Counter([entry['ip'] for entry in entries])
    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count > threshold}

    # Summary DataFrame
    summary_df = pd.DataFrame(list(ip_counts.items()), columns=['IP', 'Failed Attempts']).sort_values('Failed Attempts', ascending=False)
    save_csv(summary_df)

    # Display top attackers
    print("\n=== Top Attackers ===")
    print(f"{'IP Address':<15} | {'Failed Attempts':<15}")
    print("-"*33)
    for ip, count in summary_df.values:
        print(f"{ip:<15} | {count:<15}")

    # Display suspicious IPs
    if suspicious_ips:
        print("\n⚠️ Suspicious IPs (above threshold):")
        for ip, count in suspicious_ips.items():
            print(f"{ip} — {count} failed attempts")
    else:
        print("\nNo IPs exceeded the threshold.")

    # Generate charts
    plot_top_attackers(entries)
    plot_attempts_over_time(entries)

if __name__ == "__main__":
    main()
