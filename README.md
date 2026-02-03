
# CyberPWN

CyberPWN is a custom software UI and backend designed to turn your CB1 (with touchscreen) into a powerful pentesting device—similar to the ESP32 Marauder or Flipper Zero. The current hardware setup uses a CB1 board and an LG Flip 125DL as the web viewer.

## Features

- Web-based dashboard for pentesting tools and attacks
- Designed for touchscreen use
- Backend powered by Flask (`server.py`)
- Modular, extensible, and always-on via systemd

## Hardware Requirements

- CB1 board with touchscreen
- LG Flip 125DL (or any device with a web browser) for viewing the dashboard

## Software Dependencies (ARM)

Install the required system tools and Python packages:

```bash
sudo apt update
sudo apt install -y aircrack-ng mdk3 hostapd hcxdumptool hcxtools nmap tcpdump network-manager iw dnsmasq bluez cron python3-pip python3-dev build-essential
pip3 install scapy
```

> **Note:** Most attacks require root privileges. Run the Flask app as root or with `sudo`.

## Running as a Service (systemd)

To run the web server 24/7 (auto-start on boot, restart on crash):

```bash
cd /path/to/CyberPWN
sudo bash scripts/install_service.sh
```

- Access the dashboard:  
	- On WiFi: `http://<device-ip>:5000`
	- On Evil Twin AP: `http://192.168.4.1:5000`
- Service management:
	- Status: `sudo systemctl status cyberpwn`
	- Logs: `sudo journalctl -u cyberpwn -f`
	- Stop: `sudo systemctl stop cyberpwn`
	- Disable: `sudo systemctl disable cyberpwn`

## Project Structure

- `server.py` — Main backend Flask server (in the root directory)
- `templates/` — HTML templates (e.g., `index.html` for login, `success.html` for dashboard)
- `scripts/` — Helper scripts (e.g., install/start/stop service)
- `bruce_env/` — Python virtual environment (optional, recommended)

---

Let me know if you want to add usage examples, screenshots, or more technical details!

