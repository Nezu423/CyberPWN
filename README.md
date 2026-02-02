CyberPWN is a software UI and BackEnd im designing to use my CB1 As a pentesting device to do things like ESP32 
Marauder does and FlipperZero, the hardware right now is a CB1 with a touchsreen. And an LG Flip 125DL as the 
Web Viewer.

## Dependencies ARM

Make sure all required system tools and Python packages are installed on your ARM device.
```sudo apt update
sudo apt install -y aircrack-ng mdk3 hostapd hcxdumptool hcxtools nmap tcpdump network-manager iw dnsmasq bluez cron python3-pip python3-dev build-essential
pip3 install scapy
```
 Run as Root or with Sudo
Most attacks require root privileges. Run your Flask app with sudo:



## Always-on (systemd)

To run the web server 24/7 (start on boot, restart on crash):

```bash
cd /path/to/CyberPWN
sudo bash scripts/install_service.sh
```

Then: `http://<device-ip>:5000` (on WiFi) or `http://192.168.4.1:5000` when the evil-twin AP is up.

- Status: `sudo systemctl status cyberpwn`
- Logs: `sudo journalctl -u cyberpwn -f`
- Stop: `sudo systemctl stop cyberpwn`
- Disable on boot: `sudo systemctl disable cyberpwn`

The way it is laid out is there is a /Bruce directory. and in there is a server.py that executes all the code on the CB1 as the backend. in /templates there is index.html which is the login screen. That will redirect you to success.html where that is the main dashboard. 

