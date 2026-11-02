
import subprocess
import socket
import platform
import re
from datetime import datetime


def check_ping(host="8.8.8.8", count=4, timeout=2):

    result = {
        "success": False,
        "host": host,
        "packets_sent": count,
        "packets_received": 0,
        "packet_loss": None,
        "average_latency": None,
        "min_latency": None,
        "max_latency": None,
        "error": None
    }

    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping", "-n", str(count),
            "-w", str(timeout * 1000), host
        ]
    else:
        command = [
            "ping", "-c", str(count),
            "-W", str(timeout), host
        ]

    try:
        output = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=(count * (timeout + 2)) + 5
        )

        text_output = output.stdout + output.stderr

        received = 0

        if system == "windows":
            match = re.search(
                r"Received = (\d+)",
                text_output,
                re.IGNORECASE
            )

            if match:
                received = int(match.group(1))
        else:
            match = re.search(
                r"(\d+) received",
                text_output
            )

            if match:
                received = int(match.group(1))

        result["packets_received"] = received
        result["packet_loss"] = round(
            ((count - received) / count) * 100,
            2
        )

        latency_values = []

        for match in re.findall(
            r"time[=<]([\d.]+)\s*ms",
            text_output
        ):
            latency_values.append(float(match))

        if latency_values:
            result["average_latency"] = round(
                sum(latency_values) / len(latency_values),
                2
            )

            result["min_latency"] = round(
                min(latency_values),
                2
            )

            result["max_latency"] = round(
                max(latency_values),
                2
            )

        result["success"] = received > 0

        if received == 0:
            result["error"] = (
                "No ping replies received. "
                "The host may block ICMP or be unreachable."
            )

    except subprocess.TimeoutExpired:
        result["error"] = "Ping command timed out."

    except Exception as error:
        result["error"] = str(error)

    return result


def check_dns(domain="google.com"):

    result = {
        "success": False,
        "domain": domain,
        "ip_address": None,
        "response_time_ms": None,
        "error": None
    }

    try:
        start = datetime.now()

        ip_address = socket.gethostbyname(domain)

        end = datetime.now()

        response_time = (
            end - start
        ).total_seconds() * 1000

        result.update({
            "success": True,
            "ip_address": ip_address,
            "response_time_ms": round(response_time, 2)
        })

    except Exception as error:
        result["error"] = str(error)

    return result


def check_internet():

    result = {
        "success": False,
        "host": "8.8.8.8",
        "response_time_ms": None,
        "error": None
    }

    try:
        start = datetime.now()

        connection = socket.create_connection(
            ("8.8.8.8", 53),
            timeout=5
        )

        connection.close()

        end = datetime.now()

        result["success"] = True
        result["response_time_ms"] = round(
            (end - start).total_seconds() * 1000,
            2
        )

    except Exception as error:
        result["error"] = str(error)

    return result


def run_diagnostics():

    internet = check_internet()
    ping = check_ping()
    dns = check_dns()

    recommendations = []

    if not internet["success"]:
        recommendations.append(
            "Internet connection could not be established. "
            "Check your network connection."
        )

    if not ping["success"]:
        recommendations.append(
            "Ping received no replies. The destination may block "
            "ICMP traffic or be unreachable."
        )
    elif ping["packet_loss"] > 0:
        recommendations.append(
            "Packet loss detected. Check Wi-Fi signal, "
            "network congestion and connectivity."
        )

    if not dns["success"]:
        recommendations.append(
            "DNS resolution failed. Check your DNS settings."
        )

    if (
        ping["average_latency"] is not None
        and ping["average_latency"] > 150
    ):
        recommendations.append(
            "High ping latency detected. Check network "
            "congestion or connection quality."
        )

    if not recommendations:
        recommendations.append(
            "No problems detected by these basic diagnostic checks."
        )

    return {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "internet": internet,
        "ping": ping,
        "dns": dns,
        "recommendations": recommendations
    }
