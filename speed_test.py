import speedtest


def run_speed_test():

    tester = speedtest.Speedtest()

    tester.get_best_server()

    download_speed = tester.download() / 1_000_000
    upload_speed = tester.upload() / 1_000_000
    ping = tester.results.ping

    return {
        "download": round(download_speed, 2),
        "upload": round(upload_speed, 2),
        "ping": round(ping, 2)
    }
