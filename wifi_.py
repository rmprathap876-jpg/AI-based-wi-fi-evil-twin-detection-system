import subprocess
import time
import csv

def scan_wifi_detailed():
    try:
        subprocess.run(["netsh", "wlan", "scan"], shell=True)
        time.sleep(3)

        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            shell=True
        ).decode("utf-8", errors="ignore")

        lines = output.split("\n")
        current_network = {}
        full_output_text = []

        print("\nDetailed Nearby Wi-Fi Networks:\n")
        full_output_text.append("Detailed Nearby Wi-Fi Networks:\n")

        for line in lines:
            line = line.strip()

            if line.startswith("SSID"):
                if current_network:
                    text_block = print_network(current_network)
                    full_output_text.append(text_block)
                    current_network = {}
                current_network["SSID"] = line.split(":", 1)[1].strip()

            elif line.startswith("BSSID"):
                current_network["BSSID"] = line.split(":", 1)[1].strip()

            elif line.startswith("Signal"):
                current_network["Signal"] = line.split(":", 1)[1].strip()

            elif line.startswith("Band"):
                current_network["Band"] = line.split(":", 1)[1].strip()

            elif line.startswith("Channel"):
                current_network["Channel"] = line.split(":", 1)[1].strip()

            elif line.startswith("Authentication"):
                current_network["Authentication"] = line.split(":", 1)[1].strip()

            elif line.startswith("Cipher"):
                current_network["Cipher"] = line.split(":", 1)[1].strip()

            elif line.startswith("Radio type"):
                current_network["Radio type"] = line.split(":", 1)[1].strip()

            elif line.startswith("Network type"):
                current_network["Network type"] = line.split(":", 1)[1].strip()

        if current_network:
            text_block = print_network(current_network)
            full_output_text.append(text_block)

        save_to_csv(full_output_text)

        print("\nOutput also saved to wifi_output.csv")

    except Exception as e:
        print("Error:", e)


def print_network(data):
    block = ""
    block += "Name : " + data.get("SSID", "N/A") + "\n"
    block += "Description : N/A (Not available unless connected)\n"
    block += "GUID : N/A\n"
    block += "Physical address : N/A\n"
    block += "Interface type : N/A\n"
    block += "State : Not connected\n"
    block += "SSID : " + data.get("SSID", "N/A") + "\n"
    block += "AP BSSID : " + data.get("BSSID", "N/A") + "\n"
    block += "Band : " + data.get("Band", "N/A") + "\n"
    block += "Channel : " + data.get("Channel", "N/A") + "\n"
    block += "Network type : " + data.get("Network type", "N/A") + "\n"
    block += "Radio type : " + data.get("Radio type", "N/A") + "\n"
    block += "Authentication : " + data.get("Authentication", "N/A") + "\n"
    block += "Cipher : " + data.get("Cipher", "N/A") + "\n"
    block += "Connection mode : N/A\n"
    block += "Receive rate (Mbps) : N/A\n"
    block += "Transmit rate (Mbps) : N/A\n"
    block += "Signal : " + data.get("Signal", "N/A") + "\n"
    block += "Rssi : Not directly available\n"
    block += "Profile : N/A\n"
    block += "QoS MSCS Configured : N/A\n"
    block += "QoS Map Configured : N/A\n"
    block += "QoS Map Allowed by Policy : N/A\n"
    block += "-" * 50 + "\n"

    print(block)
    return block

def save_to_csv(text_blocks):
    with open("wifi_output.csv", mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        # Excel header
        writer.writerow([
            "Name", "SSID", "BSSID", "Band", "Channel",
            "Network type", "Radio type",
            "Authentication", "Cipher", "Signal"
        ])

        for block in text_blocks:
            lines = block.split("\n")
            data = {}

            for line in lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    data[key.strip()] = value.strip()

            if "Name" in data:
                writer.writerow([
                    data.get("Name", ""),
                    data.get("SSID", ""),
                    data.get("AP BSSID", ""),
                    data.get("Band", ""),
                    data.get("Channel", ""),
                    data.get("Network type", ""),
                    data.get("Radio type", ""),
                    data.get("Authentication", ""),
                    data.get("Cipher", ""),
                    data.get("Signal", "")
                ])


scan_wifi_detailed()