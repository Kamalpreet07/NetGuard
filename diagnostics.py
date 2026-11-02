import platform
import subprocess
import socket
import time


def check_ping(host="8.8.8.8"):

    system = platform.system().lower()

    if system == "windows":
        command = ["ping", "-n", "4", host]
    else:
        command = ["ping", "-c", "4", host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout

        if result.returncode == 0:
            return {
                "status": "Reachable",
                "details": output
            }

        return {
            "status": "Not reachable",
            "details": output
        }

    except Exception as error:
        return {
            "status": "Error",
            "details": str(error)
        }


def check_dns(domain="google.com"):

    try:
        start = time.time()

        ip_address = socket.gethostbyname(domain)

        end = time.time()

        response_time = (end - start) * 1000

        return {
            "status": "Working",
            "ip": ip_address,
            "response_time": round(response_time, 2)
        }

    except Exception as error:

        return {
            "status": "Failed",
            "ip": "Not available",
            "response_time": None,
            "error": str(error)
        }


def get_suggestions(ping_status, dns_status):

    suggestions = []

    if ping_status != "Reachable":
        suggestions.append(
            "Check your Wi-Fi or Ethernet connection and router."
        )

    if dns_status != "Working":
        suggestions.append(
            "Check your DNS settings or try another DNS resolver."
        )

    if not suggestions:
        suggestions.append(
            "Basic connectivity checks passed. "
            "If the internet is still slow, check Wi-Fi signal, "
            "router load and ISP performance."
        )

    return suggestions
