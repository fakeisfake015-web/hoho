#!/usr/bin/env python3
"""
Challenge 13: SSRF (Server-Side Request Forgery)
Points: 750
Flag: JCOECTF{ssrf_1nt3rn4l_4cc3ss_2024}
"""

from flask import Flask, request, jsonify
import requests
import re

app = Flask(__name__)

# Internal service (simulated)
INTERNAL_FLAG = "JCOECTF{ssrf_1nt3rn4l_4cc3ss_2024}"

@app.route('/')
def index():
    return '''
    <html><body style="font-family: monospace; padding: 40px;">
    <h1>🌐 URL Fetcher Service</h1>
    <p>Fetch content from any URL!</p>
    
    <form action="/fetch" method="POST">
        <input type="text" name="url" placeholder="https://example.com" size="60"><br><br>
        <button type="submit">Fetch URL</button>
    </form>
    
    <h3>Protection:</h3>
    <ul>
        <li>✅ localhost blocked</li>
        <li>✅ 127.0.0.1 blocked</li>
        <li>✅ Private IPs blocked</li>
    </ul>
    
    <p><i>Hint: Filters can be bypassed with creativity...</i></p>
    </body></html>
    '''

def is_safe_url(url):
    """Check if URL is safe (weak filter)"""
    url_lower = url.lower()
    
    # Blacklist
    blacklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254']
    
    for blocked in blacklist:
        if blocked in url_lower:
            return False
    
    # Check for private IPs (weak check)
    if re.search(r'192\.168\.|10\.|172\.', url):
        return False
    
    return True

@app.route('/fetch', methods=['POST'])
def fetch():
    url = request.form.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Security check (bypassable!)
    if not is_safe_url(url):
        return jsonify({'error': 'Blocked: Access to internal resources not allowed'}), 403
    
    try:
        # Vulnerable SSRF
        resp = requests.get(url, timeout=3)
        return jsonify({
            'success': True,
            'status_code': resp.status_code,
            'content': resp.text[:1000]  # Limit content
        })
    except Exception as e:
        return jsonify({'error': f'Fetch error: {str(e)}'}), 500

@app.route('/internal/admin')
def internal_admin():
    """Internal admin endpoint"""
    # Only accessible from localhost
    if request.remote_addr not in ['127.0.0.1', 'localhost']:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'admin': True,
        'flag': INTERNAL_FLAG
    })

if __name__ == '__main__':
    print("[*] SSRF Challenge running on port 9013")
    print("[*] Try to access /internal/admin")
    app.run(host='0.0.0.0', port=9013, debug=False)
