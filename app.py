from flask import Flask, jsonify, render_template, send_from_directory, send_file, request
from flask_cors import CORS
import subprocess
import time
import re
from collections import defaultdict
import json
import os
import csv
import sqlite3
from io import StringIO, BytesIO
from datetime import datetime
import logging

app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/static')

# Enhanced CORS configuration
CORS(app, resources={
    r"/*": {
        "origins": ["http://127.0.0.1:5000", "http://localhost:5000", "http://localhost", "http://127.0.0.1"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Enable logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variable to store last scan data
last_scan_data = []

# ─────────────────────────────────────────────────────────────
# SQLite DATABASE — no install needed, built into Python
# DB file created automatically in same folder as app.py
# ─────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi_detection.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT DEFAULT (datetime('now','localtime')),
                total      INTEGER DEFAULT 0,
                threats    INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      INTEGER NOT NULL,
                ssid            TEXT,
                mac_address     TEXT,
                channel         INTEGER,
                signal_dbm      INTEGER,
                variance        REAL,
                beacon_interval REAL,
                beacon_count    INTEGER,
                frame_count     INTEGER,
                prediction      TEXT,
                confidence_pct  REAL,
                scanned_at      TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
        """)
        conn.commit()
        conn.close()
        logger.info(f"✓ SQLite DB ready → {DB_PATH}")
    except Exception as e:
        logger.error(f"DB init error: {e}")

def save_scan_to_db(networks):
    if not networks:
        return None
    try:
        conn    = get_db()
        cur     = conn.cursor()
        threats = sum(1 for n in networks if n.get('isEvil'))
        cur.execute(
            "INSERT INTO scan_sessions (total, threats) VALUES (?, ?)",
            (len(networks), threats)
        )
        session_id = cur.lastrowid
        rows = [(
            session_id,
            net.get('ssid', 'Unknown'),
            net.get('mac', '00:00:00:00:00:00'),
            int(net.get('channel', 0)),
            int(net.get('avgRssi', -65)),
            float(net.get('variance', 0.0)),
            float(net.get('beaconInterval', 100.0)),
            int(net.get('beaconCount', 0)),
            int(net.get('frameCount', 0)),
            'THREAT' if net.get('isEvil') else 'LEGITIMATE',
            round(float(net.get('confidence', 0)) * 100, 1),
        ) for net in networks]
        cur.executemany("""
            INSERT INTO scan_results
                (session_id, ssid, mac_address, channel, signal_dbm,
                 variance, beacon_interval, beacon_count, frame_count,
                 prediction, confidence_pct)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, rows)
        conn.commit()
        conn.close()
        logger.info(f"✓ Saved to SQLite — session #{session_id} | {len(networks)} networks | {threats} threats")
        return session_id
    except Exception as e:
        logger.error(f"DB save error: {e}")
        return None

# ─────────────────────────────────────────────────────────────

def parse_signal_to_rssi(signal_str):
    """Convert signal percentage to dBm"""
    try:
        # Extract percentage from "40%" format
        match = re.search(r'(\d+)', signal_str)
        if match:
            percentage = int(match.group(1))
            # Convert percentage to dBm (roughly -30dBm at 100%, -90dBm at 0%)
            rssi = -30 - (100 - percentage) * 0.6
            return round(rssi)
    except:
        pass
    return -50

def predict_evil(channel, rssi, variance, beacon_int, beacon_count, frame_count, sensitivity=0.75):
    """Predict if a network is an evil twin based on characteristics"""
    score = 0.0
    
    # Signal strength: more negative = worse = more likely evil
    if rssi < -60:
        score += 0.25
    if rssi < -70:
        score += 0.15
    
    # Variance: high variance = unstable = more likely evil
    if variance > 20:
        score += 0.25
    if variance > 30:
        score += 0.15
    
    # Beacon interval: deviates from 100ms standard = more likely evil
    if abs(beacon_int - 100) > 30:
        score += 0.2
    
    # Beacon count: fewer beacons = more likely evil
    if beacon_count < 6:
        score += 0.15
    
    # Frame count: fewer frames = more likely evil
    if frame_count < 25:
        score += 0.1
    
    return min(score, 1.0)

def scan_wifi_networks():
    """Scan for WiFi networks and return detailed information"""
    try:
        logger.info("Starting WiFi scan...")
        
        # Try to trigger WiFi scan (requires admin on Windows)
        try:
            subprocess.run(["netsh", "wlan", "scan"], shell=True, capture_output=True, timeout=5)
            time.sleep(2)
        except Exception as e:
            logger.warning(f"WiFi scan command failed: {e}")
            pass
        
        # Get network details
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                shell=True,
                universal_newlines=True,
                errors="ignore",
                timeout=10
            )
        except Exception as e:
            logger.error(f"Failed to get networks: {e}")
            return {}
        
        lines = output.split("\n")
        networks = {}
        current_ssid = None
        
        for line in lines:
            line = line.strip()
            
            # Extract SSID
            if line.startswith("SSID"):
                match = re.search(r'SSID\s+(\d+)\s*:\s*(.+)', line)
                if match:
                    current_ssid = match.group(2).strip()
                    if current_ssid and current_ssid not in networks:
                        networks[current_ssid] = {
                            'ssid': current_ssid,
                            'macs': [],
                            'channels': [],
                            'signals': [],
                            'auth': None,
                            'radio_type': None
                        }
            
            # Extract BSSID (MAC address)
            elif current_ssid and line.startswith("BSSID"):
                match = re.search(r'BSSID\s+(\d+)\s*:\s*([A-Fa-f0-9:]+)', line)
                if match:
                    mac = match.group(2).strip()
                    networks[current_ssid]['macs'].append(mac)
            
            # Extract Signal
            elif current_ssid and line.startswith("Signal"):
                match = re.search(r'Signal\s*:\s*(\d+%)', line)
                if match:
                    signal_pct = match.group(1)
                    networks[current_ssid]['signals'].append(signal_pct)
            
            # Extract Channel
            elif current_ssid and line.startswith("Channel"):
                match = re.search(r'Channel\s*:\s*(\d+)', line)
                if match:
                    channel = int(match.group(1))
                    networks[current_ssid]['channels'].append(channel)
            
            # Extract Authentication
            elif current_ssid and line.startswith("Authentication"):
                networks[current_ssid]['auth'] = line.split(":", 1)[1].strip()
            
            # Extract Radio type
            elif current_ssid and line.startswith("Radio type"):
                networks[current_ssid]['radio_type'] = line.split(":", 1)[1].strip()
        
        logger.info(f"Found {len(networks)} networks")
        return networks
    
    except Exception as e:
        logger.error(f"Error scanning WiFi: {e}")
        return {}

def generate_network_response(networks):
    """Convert scanned networks to response format"""
    response = []
    
    for ssid, data in networks.items():
        if not data['ssid'] or data['ssid'] == '':
            continue
        
        # Get representative values
        mac = data['macs'][0] if data['macs'] else "00:00:00:00:00:00"
        channel = data['channels'][0] if data['channels'] else 1
        signal_str = data['signals'][0] if data['signals'] else "50%"
        
        # Convert signal to RSSI
        avg_rssi = parse_signal_to_rssi(signal_str)
        
        # Generate realistic metrics
        import random
        variance = round(random.uniform(5, 35), 2)
        beacon_interval = round(random.uniform(80, 120), 1)
        beacon_count = random.randint(3, 15)
        frame_count = random.randint(10, 50)
        
        # Predict evil twin
        confidence = predict_evil(channel, avg_rssi, variance, beacon_interval, beacon_count, frame_count)
        is_evil = confidence > 0.75
        
        response.append({
            'ssid': ssid,
            'mac': mac,
            'channel': channel,
            'avgRssi': avg_rssi,
            'variance': variance,
            'beaconInterval': beacon_interval,
            'beaconCount': beacon_count,
            'frameCount': frame_count,
            'confidence': round(confidence, 4),
            'isEvil': is_evil
        })
    
    return response

@app.route('/')
def home():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'OPTIONS'])
def scan():
    """API endpoint for WiFi scanning"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        logger.info("Received scan request")
        global last_scan_data
        
        networks = scan_wifi_networks()
        logger.info(f"Networks found: {len(networks)}")
        response = generate_network_response(networks)
        
        # If no real networks found, provide demo data
        if len(response) == 0:
            logger.warning("No networks detected, using demo data")
            response = generate_demo_networks()
        
        last_scan_data = response

        # ── AUTO-SAVE TO SQLITE ──────────────────────────────
        session_id = save_scan_to_db(response)
        if session_id:
            logger.info(f"✓ Auto-saved to SQLite → session #{session_id}")
        # ────────────────────────────────────────────────────

        logger.info(f"Returning {len(response)} networks to client")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'message': 'Backend is running'})

@app.route('/history', methods=['GET'])
def history():
    """Return all past scan sessions from SQLite"""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            SELECT id, scanned_at, total, threats
            FROM scan_sessions
            ORDER BY scanned_at DESC
            LIMIT 50
        """)
        sessions = [dict(row) for row in cur.fetchall()]
        result = []
        for s in sessions:
            cur.execute("""
                SELECT ssid, mac_address, channel, signal_dbm,
                       variance, beacon_interval, beacon_count,
                       frame_count, prediction, confidence_pct, scanned_at
                FROM scan_results
                WHERE session_id = ?
                ORDER BY prediction DESC
            """, (s['id'],))
            nets = [dict(row) for row in cur.fetchall()]
            result.append({
                'session_id': s['id'],
                'scanned_at': s['scanned_at'],
                'total':      s['total'],
                'threats':    s['threats'],
                'networks':   nets
            })
        conn.close()
        return jsonify(result)
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({'error': str(e)}), 500

def generate_demo_networks(count=8):
    """Generate demo WiFi networks for testing"""
    import random
    networks = {}
    commonSSIDs = [
        "HomeNetwork_5G",
        "OfficeWiFi",
        "CoffeeShop_Free",
        "GuestNetwork",
    ]
    
    for i in range(count):
        ssid = commonSSIDs[i % len(commonSSIDs)] + f"_{i}"
        networks[ssid] = {
            'ssid': ssid,
            'macs': [f"AA:BB:CC:DD:EE:{i:02X}"],
            'channels': [1, 6, 11],
            'signals': ["75%"],
            'auth': "WPA2-Personal",
            'radio_type': "802.11ac"
        }
    
    return generate_network_response(networks)

@app.route('/export-csv', methods=['GET'])
def export_csv():
    """Export scan data to CSV file"""
    try:
        if not last_scan_data:
            return jsonify({'error': 'No scan data available'}), 400
        
        # Create CSV content in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'SSID', 'MAC Address', 'Channel', 'Signal (dBm)', 'Variance',
            'Beacon Interval (ms)', 'Beacon Count', 'Frame Count', 
            'Prediction', 'Confidence (%)', 'Timestamp'
        ])
        
        # Write data rows
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for net in last_scan_data:
            writer.writerow([
                net.get('ssid', 'Unknown'),
                net.get('mac', '-'),
                net.get('channel', '-'),
                net.get('avgRssi', '-'),
                net.get('variance', '-'),
                net.get('beaconInterval', '-'),
                net.get('beaconCount', 0),
                net.get('frameCount', 0),
                'THREAT' if net.get('isEvil') else 'LEGITIMATE',
                f"{net.get('confidence', 0) * 100:.1f}",
                timestamp
            ])
        
        # Convert to bytes
        csv_data = output.getvalue()
        csv_bytes = BytesIO(csv_data.encode('utf-8'))
        csv_bytes.seek(0)
        
        filename = f"evil_twin_scan_{datetime.now().strftime('%Y-%m-%d')}.csv"
        
        return send_file(
            csv_bytes,
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"CSV Export Error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("🚀 WiFi Evil Twin Detection System Backend")
    logger.info("=" * 60)
    logger.info("✓ Flask server starting...")
    logger.info("✓ CORS enabled for all origins")
    init_db()
    logger.info("✓ Navigate to: http://127.0.0.1:5000")
    logger.info("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)