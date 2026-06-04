import socket
import requests
from datetime import datetime


# Common Ports to Scan

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306]


# Port Scanner

def scan_ports(target):
    open_ports = []

    print("\nScanning Ports...")

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"Port {port} : OPEN")
            open_ports.append(port)

        sock.close()

    return open_ports



# Security Header Checker

def check_security_headers(url):
    headers_result = {}

    security_headers = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    try:
        response = requests.get(url, timeout=5)

        print("\nChecking Security Headers...")

        for header in security_headers:
            if header in response.headers:
                headers_result[header] = "Present"
            else:
                headers_result[header] = "Missing"

            print(f"{header}: {headers_result[header]}")

        return headers_result, response.headers

    except Exception as e:
        print("Error:", e)
        return {}, {}



# Server Information

def get_server_info(response_headers):
    server = response_headers.get("Server", "Unknown")
    print(f"\nServer Information: {server}")
    return server



# Risk Assessment

def calculate_risk(open_ports, headers_result):
    risk_score = 0

    risk_score += len(open_ports)

    for status in headers_result.values():
        if status == "Missing":
            risk_score += 1

    if risk_score <= 2:
        return "Low"
    elif risk_score <= 5:
        return "Medium"
    else:
        return "High"



# Report Generator

def generate_report(target, open_ports, headers_result, server, risk):
    filename = "vulnerability_report.txt"

    with open(filename, "w") as report:
        report.write("=" * 50 + "\n")
        report.write("VULNERABILITY SCAN REPORT\n")
        report.write("=" * 50 + "\n\n")

        report.write(f"Target: {target}\n")
        report.write(f"Scan Time: {datetime.now()}\n\n")

        report.write("OPEN PORTS:\n")
        if open_ports:
            for port in open_ports:
                report.write(f"- Port {port}\n")
        else:
            report.write("No open ports detected.\n")

        report.write("\nSECURITY HEADERS:\n")
        for header, status in headers_result.items():
            report.write(f"{header}: {status}\n")

        report.write(f"\nSERVER INFO:\n{server}\n")

        report.write(f"\nRISK LEVEL: {risk}\n")

        report.write("\nRECOMMENDATIONS:\n")

        if len(open_ports) > 0:
            report.write("- Review unnecessary open ports.\n")

        for header, status in headers_result.items():
            if status == "Missing":
                report.write(f"- Enable {header}\n")

    print(f"\nReport saved as '{filename}'")


def main():

    target = input("Enter Website Domain (example.com): ").strip()

    try:
        ip = socket.gethostbyname(target)
        print(f"\nTarget IP: {ip}")

        open_ports = scan_ports(ip)

        url = f"https://{target}"

        headers_result, response_headers = check_security_headers(url)

        server = get_server_info(response_headers)

        risk = calculate_risk(open_ports, headers_result)

        print(f"\nRisk Level: {risk}")

        generate_report(
            target,
            open_ports,
            headers_result,
            server,
            risk
        )

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()