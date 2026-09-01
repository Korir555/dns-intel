from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import dns.resolver
import dns.reversename
from cryptography import x509
from cryptography.x509.oid import NameOID
import ssl
import socket
from datetime import datetime
import json

app = Flask(__name__, template_folder='templates')
CORS(app)

@app.route('/') 
def index():
    return render_template('index.html')

@app.route('/api/dns/lookup', methods=['POST'])
def dns_lookup():
    domain = request.json.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    results = {'domain': domain, 'records': {}, 'timestamp': datetime.utcnow().isoformat()}
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results['records'][rtype] = [str(rr) for rr in answers]
        except:
            pass
    
    return jsonify(results), 200

@app.route('/api/cert/info', methods=['POST'])
def cert_info():
    domain = request.json.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    try:
        cert = ssl.create_default_context().check_hostname = False
        cert = ssl.create_default_context().verify_mode = ssl.CERT_NONE
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        
        return jsonify({
            'domain': domain,
            'certificate': cert,
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'version': cert.get('version'),
            'serial': cert.get('serialNumber'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5004)
