from dockerState import DockerRunner, RouterState
from testWebsite import VulnerableWebServer
import os


def is_root():
    return os.geteuid() == 0


web_demo = VulnerableWebServer(port=8080)
web_demo.start()

runner = DockerRunner("/home/berry15/Desktop/wifi-simuliacija/raspap")

runner.start_router(RouterState.SCENARIO_OPEN_WIFI)

input("waiting for press..")

runner.stop_router()
web_demo.stop()

print("done")
