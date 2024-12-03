import re
import os  
import csv
from collections import Counter

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        log_lines = file.readlines()
    return log_lines

def extract_ips(log_lines):
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    return re.findall(ip_pattern, ' '.join(log_lines))

def extract_endpoints(log_lines):
    endpoint_pattern = r'\"[A-Z]+\s(\/[^\s]*)\sHTTP'
    return re.findall(endpoint_pattern, ' '.join(log_lines))

def count_requests_per_ip(ips):
    return Counter(ips)

def find_most_frequent_endpoint(endpoints):
    endpoint_counts = Counter(endpoints)
    most_frequent = endpoint_counts.most_common(1)[0]
    return most_frequent

def detect_suspicious_activity(log_lines, threshold=10):
    failed_attempts = {}
    for line in log_lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*"POST /login HTTP/1.1" 401', line)
        if match:
            ip = match.group(1)
            if ip in failed_attempts:
                failed_attempts[ip] += 1
            else:
                failed_attempts[ip] = 1
    
    # Filter IPs exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips

def save_to_csv(file_path, ip_counts, most_frequent_endpoint, suspicious_ips):
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Write Requests per IP
        csv_writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            csv_writer.writerow([ip, count])
        
        # Write Most Frequent Endpoint
        csv_writer.writerow([])
        csv_writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        csv_writer.writerow([most_frequent_endpoint[0], most_frequent_endpoint[1]])
        
        # Write Suspicious Activity
        if suspicious_ips:
            csv_writer.writerow([])
            csv_writer.writerow(["Suspicious Activity", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                csv_writer.writerow([ip, count])

def main():
    log_file_path = 'logs/sample.log'  # Path to your log file
    output_csv_path = 'outputs/log_analysis_results.csv'
    
    log_lines = parse_log_file(log_file_path)
    
    # Extract and count IPs
    ips = extract_ips(log_lines)
    ip_counts = count_requests_per_ip(ips)
    
    # Find the most frequent endpoint
    endpoints = extract_endpoints(log_lines)
    most_frequent_endpoint = find_most_frequent_endpoint(endpoints)
    
    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(log_lines)
    
    # Display Results
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<10}")
    for ip, count in ip_counts.items():
        print(f"{ip:<20}{count:<10}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<10}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<10}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_to_csv(output_csv_path, ip_counts, most_frequent_endpoint, suspicious_ips)

if __name__ == "__main__":
    main()
