from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import os

app = Flask(__name__)

# Load the trained model
model = joblib.load("firewall_model.pkl")

# Store detection history
detection_history = []

@app.route('/')
def index():
    """Landing page with project information"""
    return render_template('index.html')

@app.route('/detect')
def detect_page():
    """Detection page"""
    return render_template('detect.html')

@app.route('/about')
def about_page():
    """About page with team and project info"""
    return render_template('about.html')

@app.route('/api/detect', methods=['POST'])
def detect_packet():
    """API endpoint for packet detection"""
    try:
        data = request.get_json()
        
        # Extract features
        src_ip = int(data.get('src_ip'))
        dst_ip = int(data.get('dst_ip'))
        port = int(data.get('port'))
        protocol = int(data.get('protocol'))
        packet_size = int(data.get('packet_size'))
        
        # Create feature array
        packet = np.array([[src_ip, dst_ip, port, protocol, packet_size]])
        
        # Predict
        result = model.predict(packet)
        prediction = "Blocked" if result[0] == 1 else "Allowed"
        
        # Store in history
        detection_history.append({
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': port,
            'protocol': 'TCP' if protocol == 1 else 'UDP',
            'packet_size': packet_size,
            'result': prediction
        })
        
        return jsonify({
            'success': True,
            'prediction': prediction,
            'result_code': int(result[0]),
            'message': f"Packet {prediction.lower()} by firewall"
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get detection history"""
    return jsonify({
        'success': True,
        'history': detection_history[-50:]  # Return last 50 detections
    })

@app.route('/api/clear_history', methods=['POST'])
def clear_history():
    """Clear detection history"""
    global detection_history
    detection_history = []
    return jsonify({'success': True, 'message': 'History cleared'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)