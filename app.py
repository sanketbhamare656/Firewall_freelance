# app_rule_based.py - Complete working firewall with history page
from flask import Flask, render_template, request, jsonify
from datetime import datetime
import os

app = Flask(__name__)

# ============================================
# GLOBAL VARIABLES
# ============================================
detection_history = []

# ============================================
# FIREWALL RULES CONFIGURATION
# ============================================

class FirewallRules:
    def __init__(self):
        self.blocked_ports = {
            23: "Telnet - Unencrypted protocol",
            3389: "RDP - Remote Desktop vulnerable",
            445: "SMB - Ransomware attacks",
            135: "RPC - Windows vulnerabilities",
            139: "NetBIOS - Old protocol",
            1433: "MSSQL - Database attacks",
            3306: "MySQL - Database attacks",
            22: "SSH - Brute force attempts",
            25: "SMTP - Email spamming",
            21: "FTP - Unencrypted file transfer"
        }
        
        self.allowed_ports = {
            80: "HTTP - Web traffic",
            443: "HTTPS - Secure web",
            53: "DNS - Domain resolution",
            67: "DHCP - IP assignment",
            68: "DHCP - IP assignment",
            123: "NTP - Time sync"
        }
        
        self.max_packet_size = 1500
        self.min_packet_size = 64
        
        self.suspicious_ips = {
            'private': [10, 172, 192],
            'blacklisted': [1, 2, 3, 5, 7]
        }
        
        self.valid_protocols = {
            1: "TCP",
            2: "UDP",
            6: "TCP",
            17: "UDP"
        }
        
        self.attack_patterns = {
            'dos': {'min_size': 1000, 'max_size': 65535},
            'port_scan': {'ports': [21, 22, 23, 80, 443, 3389]}
        }

firewall = FirewallRules()

def analyze_packet(src_ip, dst_ip, port, protocol, packet_size):
    reasons = []
    severity = "low"
    
    if protocol not in firewall.valid_protocols:
        reasons.append(f"Invalid protocol: {protocol}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    if packet_size > firewall.max_packet_size:
        reasons.append(f"Packet too large: {packet_size} bytes (max: {firewall.max_packet_size})")
        severity = "high"
        return "BLOCK", reasons, severity
    
    if packet_size < firewall.min_packet_size:
        reasons.append(f"Packet too small: {packet_size} bytes")
        severity = "medium"
    
    if port in firewall.blocked_ports:
        reasons.append(f"Blocked port {port}: {firewall.blocked_ports[port]}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    if src_ip in firewall.suspicious_ips['private']:
        reasons.append(f"Suspicious source IP: {src_ip}")
        severity = "medium"
    
    if port in firewall.attack_patterns['port_scan']['ports']:
        reasons.append(f"Port scanning detected on port {port}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    if packet_size > firewall.attack_patterns['dos']['min_size']:
        reasons.append(f"Possible DoS attack: Large packet size {packet_size}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    if port in firewall.allowed_ports:
        reasons.append(f"Allowed port {port}: {firewall.allowed_ports[port]}")
        severity = "low"
        return "ALLOW", reasons, severity
    
    if 1024 <= port <= 49151:
        reasons.append(f"Registered port {port} - Allowed")
        severity = "medium"
        return "ALLOW", reasons, severity
    elif 49152 <= port <= 65535:
        reasons.append(f"Dynamic port {port} - Allowed")
        severity = "low"
        return "ALLOW", reasons, severity
    else:
        reasons.append(f"Unknown port {port} - Blocked")
        severity = "high"
        return "BLOCK", reasons, severity

# ============================================
# FLASK ROUTES
# ============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect')
def detect_page():
    return render_template('detect.html')

@app.route('/history')
def history_page():
    return render_template('history.html')

@app.route('/about')
def about_page():
    return render_template('about.html')

@app.route('/api/detect', methods=['POST'])
def detect_packet():
    global detection_history
    
    try:
        data = request.get_json()
        
        src_ip = int(data.get('src_ip'))
        dst_ip = int(data.get('dst_ip'))
        port = int(data.get('port'))
        protocol = int(data.get('protocol'))
        packet_size = int(data.get('packet_size'))
        
        action, reasons, severity = analyze_packet(src_ip, dst_ip, port, protocol, packet_size)
        
        prediction = action
        is_blocked = (action == "BLOCK")
        
        history_entry = {
            'id': len(detection_history) + 1,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': port,
            'protocol': firewall.valid_protocols.get(protocol, f"Unknown({protocol})"),
            'packet_size': packet_size,
            'result': prediction,
            'reasons': reasons,
            'severity': severity
        }
        
        detection_history.insert(0, history_entry)
        
        if len(detection_history) > 100:
            detection_history = detection_history[:100]
        
        return jsonify({
            'success': True,
            'prediction': prediction,
            'result_code': 1 if is_blocked else 0,
            'message': f"Packet {prediction.lower()} by firewall",
            'reasons': reasons,
            'severity': severity
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/history', methods=['GET'])
def get_history():
    global detection_history
    return jsonify({
        'success': True,
        'history': detection_history
    })

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    global detection_history
    detection_history = []
    return jsonify({'success': True, 'message': 'History cleared'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print("\n" + "="*60)
    print("🛡️  RULE-BASED FIREWALL SYSTEM")
    print("="*60)
    print(f"🌐 Server: http://localhost:{port}")
    print(f"📋 Detection Page: http://localhost:{port}/detect")
    print(f"📜 History Page: http://localhost:{port}/history")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=port)