from dockerState import DockerRunner, RouterState
from interface import RPIInterface, StateDefs
from testWebsite import VulnerableWebServer
import os, argparse

state_index = 0
is_interface_being_upd = False


def is_root():
    return os.geteuid() == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiFi Simulation Tool")
    parser.add_argument(
        "--interface", action="store_true", help="Run in hardware interface mode"
    )
    args = parser.parse_args()

    web_demo = VulnerableWebServer(port=8080)

    runner = DockerRunner("/home/berry15/Desktop/wifi-simuliacija/raspap")

    try:
        if args.interface:
            rinterface = RPIInterface()

            scenarios = [
                RouterState.SCENARIO_OPEN_WIFI,
                RouterState.SCENARIO_WPA2,
                RouterState.SCENARIO_EVIL_TWIN,
                RouterState.OFFLINE,
            ]
            state_to_led = {
                RouterState.SCENARIO_OPEN_WIFI: StateDefs.open_wifi,
                RouterState.SCENARIO_WPA2: StateDefs.wpa2_psk,
                RouterState.SCENARIO_EVIL_TWIN: StateDefs.evil_twin,
                RouterState.OFFLINE: StateDefs.READY,
            }

            rinterface.setState(StateDefs.READY)

            def on_press():
                global is_interface_being_upd, state_index

                if is_interface_being_upd == True:
                    print("[!] Still updating the interface, please wait...")
                    return

                is_interface_being_upd = True
                try:
                    rinterface.setState(StateDefs.OFF)

                    current_scenario = scenarios[state_index]
                    led_enum_member = state_to_led[current_scenario]

                    print(f"[*] Switching to: {current_scenario.name}")

                    web_demo.stop()
                    if current_scenario == RouterState.OFFLINE:
                        runner.stop_router()
                    else:
                        web_demo.start()
                        runner.start_router(current_scenario)

                    rinterface.setState(led_enum_member)
                    state_index = (state_index + 1) % len(scenarios)
                    print(f"[+] Running in {current_scenario.name} mode")
                finally:
                    is_interface_being_upd = False

            rinterface.registerPressListener(on_press)
            print(
                "Interface mode started. Press the button to cycle through scenarios."
            )
            input("Press Enter to exit...\n")

        else:
            print("Select the scenario to run:")
            print("1. Open Wi-Fi")
            print("2. WPA2-PSK")
            print("3. Evil Twin")
            choice = input("Enter the number of the scenario: ")

            if choice == "1":
                runner.start_router(RouterState.SCENARIO_OPEN_WIFI)
                web_demo.start()
            elif choice == "2":
                runner.start_router(RouterState.SCENARIO_WPA2)
                web_demo.start()
            elif choice == "3":
                runner.start_router(RouterState.SCENARIO_EVIL_TWIN)
                web_demo.start()
            else:
                print("Invalid choice. Exiting.")
                exit(1)

            input("waiting for press..")

    finally:
        runner.stop_router()
        web_demo.stop()

        print("done")
