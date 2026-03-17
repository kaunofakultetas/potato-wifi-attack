from enum import Enum
from python_on_whales import DockerClient
import os, subprocess, shutil


class RouterState(Enum):
    OFFLINE = 0
    SCENARIO_OPEN_WIFI = "open_wifi"
    SCENARIO_WPA2 = "wpa2"
    SCENARIO_EVIL_TWIN = "evil_twin"


# ENV konfiguracija raspap'ui
genericConfig: list[dict[str, str]] = [
    {"RASPI_MONITOR_ENABLED": "true"},
    {"RASPAP_WEBGUI_PORT": "8081"},
    {"RASPAP_WEBGUI_USER": "admin"},
    {"RASPAP_WEBGUI_PASS": "vuknf123"},
    {"RASPAP_COUNTRY": "LT"},
]


def get_env_for_state(state: RouterState) -> dict[str, str]:
    env_vars = {}
    for entry in genericConfig:
        env_vars.update(entry)

    return env_vars


class DockerRunner:
    compose_folder: str = ""
    current_state: RouterState = RouterState.OFFLINE
    docker_client: DockerClient
    wifi_interface = "wlan0"

    def __init__(self, compose_folder: str):
        self.compose_folder = compose_folder
        self.docker_client = DockerClient(compose_project_directory=compose_folder)

    def can_run(self) -> bool:
        return bool(
            self.compose_folder
            and os.path.exists(self.compose_folder)
            and os.path.isdir(self.compose_folder)
            and os.path.exists(os.path.join(self.compose_folder, "docker-compose.yml"))
        )

    def start_router(self, state: RouterState):
        if self.current_state != RouterState.OFFLINE:
            self.stop_router()

        print(f"[!] Starting router with state: {state}")

        # Check for old .env
        env_path = os.path.join(self.compose_folder, ".env")
        if os.path.exists(env_path):
            os.remove(env_path)

        # Create new env
        env = get_env_for_state(state)
        with open(env_path, "w") as f:
            for key, value in env.items():
                f.write(f"{key}={value}\n")

        # Update the ./raspap/hostapd/hostapd.conf file to match ./configai/(scenario name)/hostapd.conf
        scenario_name = state.value
        source_config = os.path.join("configai", scenario_name, "hostapd.conf")
        dest_config = os.path.join(
            self.compose_folder, "raspap", "hostapd", "hostapd.conf"
        )

        os.makedirs(os.path.dirname(dest_config), exist_ok=True)

        if os.path.exists(source_config):
            print(f"[!] Applying config from: {source_config}")
            shutil.copy2(source_config, dest_config)
        else:
            print(f"[W] Warning: Source config {source_config} not found!")

        # ./configai/(conf)/090_wlan0.conf -> ./raspap/dnsmasq/090_wlan0.conf
        source_dnsmasq = os.path.join("configai", scenario_name, "090_wlan0.conf")
        dest_dnsmasq = os.path.join(
            self.compose_folder, "raspap", "dnsmasq", "090_wlan0.conf"
        )

        os.makedirs(os.path.dirname(dest_dnsmasq), exist_ok=True)

        if os.path.exists(source_dnsmasq):
            print(f"[!] Applying dnsmasq config from: {source_dnsmasq}")
            shutil.copy2(source_dnsmasq, dest_dnsmasq)
        else:
            print(f"[W] Warning: Source config {source_dnsmasq} not found!")

        # Start docker container
        self.docker_client.compose.up(detach=True)
        self.current_state = state

        print("[!] Router started.")

    def stop_router(self):
        if self.current_state == RouterState.OFFLINE:
            return

        print("[!] Stopping router...")

        self.docker_client.compose.down()

        # Manually shut down wlan0 interface
        subprocess.run(
            ["sudo", "ip", "link", "set", "dev", self.wifi_interface, "down"],
            check=True,
        )

        # Remove env
        env_path = os.path.join(self.compose_folder, ".env")
        os.remove(env_path)

        self.current_state = RouterState.OFFLINE

        print("[!] Router stopped.")
