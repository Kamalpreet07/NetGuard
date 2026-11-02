
import speedtest
from datetime import datetime


def run_speed_test():

    result = {
        "success": False,
        "download": None,
        "upload": None,
        "ping": None,
        "server": None,
        "location": None,
        "sponsor": None,
        "timestamp": None,
        "error": None
    }

    try:
        tester = speedtest.Speedtest(
            secure=True,
            timeout=20
        )

        tester.get_best_server()

        server = tester.results.server

        download_bps = tester.download()
        upload_bps = tester.upload()

        results = tester.results.dict()

        result.update({
            "success": True,
            "download": round(download_bps / 1_000_000, 2),
            "upload": round(upload_bps / 1_000_000, 2),
            "ping": round(results.get("ping", 0), 2),
            "server": server.get("name", "Unknown"),
            "location": server.get("country", "Unknown"),
            "sponsor": server.get("sponsor", "Unknown"),
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "error": None
        })

    except Exception as error:

        result["error"] = str(error)

    return result


def get_speed_summary(result):

    if not result or not result.get("success"):
        return {
            "status": "Not measured",
            "message": (
                result.get("error", "Speed test has not been run.")
                if result else "Speed test has not been run."
            )
        }

    return {
        "status": "Measured",
        "download": f'{result["download"]} Mbps',
        "upload": f'{result["upload"]} Mbps',
        "ping": f'{result["ping"]} ms',
        "server": result["server"],
        "location": result["location"],
        "timestamp": result["timestamp"]
    }
