# BNRA Attack Detection and Defense System

## 📌 Overview
This is a complete system for **detecting and defending against network attacks** using a combination of **defensive modules** and **attack detection modules**. It includes:
- Network firewall rules
- Process monitoring
- Resource limits
- Network traffic analysis
- Log analysis
- Anomaly detection
- Alert generation

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/kelthuzkingdom/Pearl_Dragon.git
cd Pearl_Dragon

2. Install Dependencies

sudo apt update && sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt

3. Make Scripts Executable

chmod +x defend/*.sh
chmod +x integration/bnra_control.sh

🚀 Usage
1. Run the System

./integration/bnra_control.sh

2. Run in Docker (Optional)

docker build -t bnra_software .
docker run -d --name bnra_container bnra_software

📈 Attack Detection Module: bnra_attack_detection.py

This script detects suspicious network traffic, logs it, and sends alerts.
📦 Alert System: bnra_alerts.py

This script sends alerts to the console and logs them.
📜 Attack Alert XML: bnra_attack_alert.xml

This file defines the structure and type of attack alerts.
📦 Logs

All logs are saved in the logs/bnra_logs.txt file.
