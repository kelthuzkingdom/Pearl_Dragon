#!/bin/bash

# Monitor running processes
echo "Monitoring running processes..."
ps -ef | grep -v grep | grep -i "attack" > logs/process_monitor.lo
