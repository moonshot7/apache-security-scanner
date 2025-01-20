import requests
import logging
import smtplib
import subprocess
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

# Set up logging
logging.basicConfig(filename='/home/kali/sec_scan.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Email configuration
EMAIL_HOST = "smtp.gmail.com"  # Gmail SMTP server
EMAIL_PORT = 587  # Gmail SMTP port
EMAIL_USER = "Dahee8312@gmail.com"  # Gmail address
EMAIL_PASSWORD = "Password"  #Gmail app password
EMAIL_RECEIVER = "miin.hoo831@gmail.com"  # Receiver's email address

if not EMAIL_USER or not EMAIL_PASSWORD:
    raise ValueError("Email credentials are not set in environment variables.")

def send_email(subject, message):
    try:
        # Create the email
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        # Connect to the SMTP server
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()  # Enable TLS encryption
        server.login(EMAIL_USER, EMAIL_PASSWORD)  # Log in to the SMTP server
        server.sendmail(EMAIL_USER, EMAIL_RECEIVER, msg.as_string())  # Send the email
        server.quit()  # Disconnect from the server

        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def run_command(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logging.error(f"Command failed: {command}\nError: {result.stderr}")
            return None
    except Exception as e:
        logging.error(f"Error running command {command}: {e}")
        return None

def scan_apache_server():
    """Scan the local Apache2 server and gather information."""
    try:
        # Check SELinux status
        selinux_status = run_command("sestatus")
        logging.info(f"SELinux Status:\n{selinux_status}")

        # Check Apache status
        apache_status = run_command("systemctl status apache2")
        logging.info(f"Apache Status:\n{apache_status}")

        # Check if mod_security is enabled
        mod_security_status = run_command("apachectl -M 2>/dev/null | grep security")
        logging.info(f"mod_security Status: {'enabled' if mod_security_status else 'disabled'}")

        # Check if mod_evasive is enabled
        mod_evasive_status = run_command("apachectl -M 2>/dev/null | grep evasive")
        logging.info(f"mod_evasive Status: {'enabled' if mod_evasive_status else 'disabled'}")

        # Analyze Apache access logs for bad traffic
        bad_traffic = run_command("tail -n 100 /var/log/apache2/access.log | grep -E '404|500|403|SQL injection|XSS|brute force|suspicious'")
        logging.info(f"Bad Traffic Detected:\n{bad_traffic}")

        return selinux_status, apache_status, mod_security_status, mod_evasive_status, bad_traffic
    except Exception as e:
        logging.error(f"Error during Apache server scan: {e}")
        return None, None, None, None, None

def send_to_elasticsearch(data):
    """Send data to Elasticsearch."""
    url = "http://localhost:9200/security-scanner/_doc"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.info(f"Elasticsearch Response: {response.text}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending data to Elasticsearch: {e}")

def block_ip(ip_address):
    """Block an IP address using iptables."""
    try:
        # Block the IP address
        command = f"iptables -A INPUT -s {ip_address} -j DROP"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Blocked IP address: {ip_address}")
        else:
            logging.error(f"Failed to block IP address {ip_address}: {result.stderr}")
    except Exception as e:
        logging.error(f"Error blocking IP address {ip_address}: {e}")

def quarantine_process(process_id):
    """Quarantine (kill) a suspicious process."""
    try:
        # Kill the process
        command = f"kill -9 {process_id}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Quarantined process: {process_id}")
        else:
            logging.error(f"Failed to quarantine process {process_id}: {result.stderr}")
    except Exception as e:
        logging.error(f"Error quarantining process {process_id}: {e}")

def generate_alert(message):
    """Generate an alert and send it to Elasticsearch and via email."""
    # Send alert to Elasticsearch
    alert_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "security_alert",
        "message": message
    }
    send_to_elasticsearch(alert_data)

    # Send alert via email
    email_subject = "Security Alert: Bad Traffic Detected"
    email_message = f"Security Alert:\n\n{message}"
    send_email(email_subject, email_message)

    # Block IP addresses and quarantine processes if bad traffic is detected
    if "Bad traffic detected" in message:
        # Extract IP addresses from the bad traffic logs
        ip_addresses = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", message)
        for ip in ip_addresses:
            block_ip(ip)

        # Extract process IDs from the bad traffic logs (if applicable)
        process_ids = re.findall(r"PID: (\d+)", message)
        for pid in process_ids:
            quarantine_process(pid)

if __name__ == "__main__":
    # Perform Apache server scan
    selinux_status, apache_status, mod_security_status, mod_evasive_status, bad_traffic = scan_apache_server()

    # Prepare data for Elasticsearch
    if selinux_status and apache_status:
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": "security_scan",
            "status": "completed",
            "details": {
                "selinux_status": "enabled" if "enabled" in selinux_status.lower() else "disabled",
                "apache_status": "active" if "active" in apache_status.lower() else "inactive",
                "mod_security_status": "enabled" if mod_security_status else "disabled",
                "mod_evasive_status": "enabled" if mod_evasive_status else "disabled",
                "bad_traffic_detected": bool(bad_traffic.strip()) if bad_traffic else False  # Handle None case
            }
        }

        # Send data to Elasticsearch
        send_to_elasticsearch(data)

        # Generate alerts if bad traffic is detected
        if bad_traffic and bad_traffic.strip():  # Check if bad_traffic is not None and not empty
            alert_message = f"Bad traffic detected on Apache server:\n{bad_traffic}"
            generate_alert(alert_message)
    else:
        logging.error("Apache server scan failed. No data sent to Elasticsearch.")
