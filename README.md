CyberPWN is a software UI and BackEnd im designing to use my CB1 As a pentesting device to do things like ESP32 
Marauder does and FlipperZero, the hardware right now is a CB1 with a touchsreen. And an LG Flip 125DL as the 
Web Viewer.

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
