from dockerState import DockerRunner, RouterState
from testWebsite import VulnerableWebServer
import os


def is_root():
    return os.geteuid() == 0


web_demo = VulnerableWebServer(port=8080)
web_demo.start()

runner = DockerRunner("/home/berry15/Desktop/wifi-simuliacija/raspap")

print("Select the scenario to run:")
print("1. Open Wi-Fi")
print("2. WPA2-PSK")
print("3. Evil Twin")
choice = input("Enter the number of the scenario: ")

if choice == "1":
    runner.start_router(RouterState.SCENARIO_OPEN_WIFI)
elif choice == "2":
    runner.start_router(RouterState.SCENARIO_WPA2)
elif choice == "3":
    runner.start_router(RouterState.SCENARIO_EVIL_TWIN)
else:
    print("Invalid choice. Exiting.")
    exit(1)

input("waiting for press..")

runner.stop_router()
web_demo.stop()

print("done")
