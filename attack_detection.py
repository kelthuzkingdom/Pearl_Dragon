import requests
import json
import logging
import time

# Set up logging
logging.basicConfig(filename='logs/bnra_logs.txt', level=logging.INFO)

# Simulated attack detection logic
def detect_attack():
    try:
        # Example: Check for suspicious network traffic
        response = requests.get("http://localhost:8080/network-traffic")
        data = json.loads(response.text)

        if data['suspicious_activity']:
            logging.warning("Suspicious network traffic detected!")
            print("🚨 Suspicious network traffic detected!")
            # Trigger alert
            send_alert("Network attack detected", "Suspicious traffic detected")

    except Exception as e:
        logging.error(f"Error detecting attack: {e}")
        print(f"⚠️ Error: {e}")

def send_alert(subject, message):
    print(f"🚨 Alert: {subject}")
    print(f"Message: {message}")
    # Add logic to send alerts to Slack, email, etc.

if __name__ == "__main__":
    while True:
        detect_attack()
        time.sleep(10)  # Check every 10 seconds
