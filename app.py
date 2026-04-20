# app_rule_based.py - Fixed with correct allow/block logic
from flask import Flask, render_template, request, jsonify
from datetime import datetime
import os

app = Flask(__name__)

# ============================================
# GLOBAL VARIABLES
# ============================================
detection_history = []

# ============================================
# FIXED FIREWALL RULES
# ============================================

class FirewallRules:
    def __init__(self):
        # ONLY these ports are BLOCKED (attack ports)
        self.blocked_ports = {
            23: "Telnet - Unencrypted, easily hacked",
            3389: "RDP - Common ransomware entry point",
            445: "SMB - EternalBlue, WannaCry ransomware",
            135: "RPC - Windows vulnerabilities",
            139: "NetBIOS - Old protocol, security risks",
            1433: "MSSQL - SQL injection attacks",
            3306: "MySQL - Database attacks",
            25: "SMTP - Email spamming",
            110: "POP3 - Old protocol",
            143: "IMAP - Old protocol"
        }
        
        # ALL these ports are ALLOWED (safe ports)
        self.allowed_ports = {
            80: "HTTP - Web browsing",
            443: "HTTPS - Secure web",
            53: "DNS - Domain name resolution",
            22: "SSH - Secure remote access",
            21: "FTP - File transfer",
            67: "DHCP - IP assignment",
            68: "DHCP - IP assignment",
            123: "NTP - Time synchronization",
            8080: "HTTP-Alt - Web proxy",
            3000: "React/Node - Development",
            5000: "Flask - Python web apps",
            8000: "Django - Python web apps",
            27017: "MongoDB - Database",
            5432: "PostgreSQL - Database",
            6379: "Redis - Cache server"
        }
        
        # Packet size limits
        self.max_normal_size = 1500  # Normal MTU
        self.dos_threshold = 3000     # DoS attack threshold
        
        # Suspicious source IPs (only these are truly malicious)
        self.blacklisted_ips = [1, 2, 3, 4, 5, 6, 7, 8, 9]  # Known malicious sources
        
        # Protocol validation
        self.valid_protocols = {1: "TCP", 2: "UDP", 6: "TCP", 17: "UDP"}

firewall = FirewallRules()

# ============================================
# FIXED PACKET ANALYSIS FUNCTION
# ============================================

def analyze_packet(src_ip, dst_ip, port, protocol, packet_size):
    """
    Analyze packet - FIXED LOGIC
    Priority: 1. Protocol → 2. Port Blocklist → 3. DoS → 4. Blacklist → 5. Allow
    """
    reasons = []
    severity = "low"
    
    # 1. Check protocol validity
    if protocol not in firewall.valid_protocols:
        reasons.append(f"Invalid protocol: {protocol}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    protocol_name = firewall.valid_protocols.get(protocol, "Unknown")
    
    # 2. Check if port is BLOCKED (attack ports)
    if port in firewall.blocked_ports:
        reasons.append(f"BLOCKED: Port {port} - {firewall.blocked_ports[port]}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    # 3. Check for DoS attack (very large packets)
    if packet_size > firewall.dos_threshold:
        reasons.append(f"BLOCKED: Possible DoS attack - Packet size {packet_size} bytes exceeds {firewall.dos_threshold}")
        severity = "high"
        return "BLOCK", reasons, severity
    
    # 4. Check blacklisted source IPs
    if src_ip in firewall.blacklisted_ips:
        reasons.append(f"BLOCKED: Source IP {src_ip} is blacklisted")
        severity = "high"
        return "BLOCK", reasons, severity
    
    # 5. Check packet size warning (not block, just warning)
    if packet_size > firewall.max_normal_size:
        reasons.append(f"⚠️ Warning: Large packet size {packet_size} bytes (normal max: {firewall.max_normal_size})")
        severity = "medium"
        # NOT BLOCKING - just warning
    
    # 6. Check if port is ALLOWED
    if port in firewall.allowed_ports:
        reasons.append(f"ALLOWED: Port {port} - {firewall.allowed_ports[port]}")
        severity = "low"
        return "ALLOW", reasons, severity
    
    # 7. Check registered ports (1024-49151) - usually safe
    if 1024 <= port <= 49151:
        reasons.append(f"ALLOWED: Registered port {port} - Application specific")
        severity = "low"
        return "ALLOW", reasons, severity
    
    # 8. Check dynamic ports (49152-65535) - temporary ports
    elif 49152 <= port <= 65535:
        reasons.append(f"ALLOWED: Dynamic/Ephemeral port {port}")
        severity = "low"
        return "ALLOW", reasons, severity
    
    # 9. Default - ALLOW (changed from BLOCK to ALLOW)
    else:
        reasons.append(f"ALLOWED: Port {port} - No specific rule, allowing by default")
        severity = "low"
        return "ALLOW", reasons, severity

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
        
        print(f"\n📦 Analyzing: SRC={src_ip}, DST={dst_ip}, PORT={port}, PROTO={protocol}, SIZE={packet_size}")
        
        # Analyze packet
        action, reasons, severity = analyze_packet(src_ip, dst_ip, port, protocol, packet_size)
        
        prediction = action
        is_blocked = (action == "BLOCK")
        
        print(f"🎯 Result: {prediction}, Severity: {severity}")
        print(f"📋 Reasons: {reasons}")
        
        # Store in history
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
        print(f"❌ Error: {str(e)}")
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

@app.route('/api/rules', methods=['GET'])
def get_rules():
    return jsonify({
        'success': True,
        'rules': {
            'blocked_ports': list(firewall.blocked_ports.keys()),
            'allowed_ports': list(firewall.allowed_ports.keys()),
            'max_normal_size': firewall.max_normal_size,
            'dos_threshold': firewall.dos_threshold,
            'blacklisted_ips': firewall.blacklisted_ips
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print("\n" + "="*70)
    print("🛡️  NETGUARD FIREWALL - FIXED VERSION")
    print("="*70)
    print(f"🌐 Server: http://localhost:{port}")
    print("\n📋 FIREWALL RULES:")
    print("-"*50)
    print(f"🚫 BLOCKED Ports: {list(firewall.blocked_ports.keys())}")
    print(f"✅ ALLOWED Ports: {list(firewall.allowed_ports.keys())}")
    print(f"📦 Normal Packet Size: {firewall.max_normal_size} bytes")
    print(f"💣 DoS Threshold: {firewall.dos_threshold} bytes")
    print(f"⚠️ Blacklisted IPs: {firewall.blacklisted_ips}")
    print("="*70)
    print("\n💡 NOTE: By default, unknown ports are ALLOWED")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=port)