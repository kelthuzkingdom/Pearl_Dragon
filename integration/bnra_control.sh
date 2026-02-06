#!/bin/bash

# Start Defend Modules
echo "Starting Defend Modules..."
./defend/firewall_rules.sh
./defend/process_monitor.sh
./defend/resource_limits.sh

# Start Attack Detection Modules
echo "Starting Attack Detection Modules..."
python3 attack_detection/network_traffic_analysis.py
python3 attack_detection/log_analysis.py
python3 attack_detection/anomaly_detection.py

# Alert System
echo "Starting Alert System..."
python3 integration/bnra_alerts.py
