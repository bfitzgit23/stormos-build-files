#!/usr/bin/env python3
import subprocess
import shutil
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app) # Allow the HTML file to talk to this Python script

def get_pacman_packages(query):
    """Search Pacman DB"""
    try:
        # -Ss searches remote db, -Qs would search local
        result = subprocess.run(['pacman', '-Ss', query], capture_output=True, text=True, timeout=10)
        lines = result.stdout.split('\n')
        packages = []
        i = 0
        while i < len(lines):
            line = lines[i]
            # Line format: repo/name version
            if line.strip() and not line.startswith(' '):
                parts = line.split()
                if len(parts) >= 2:
                    # Extract name (handles repo/name format)
                    name_part = parts[0]
                    if '/' in name_part:
                        name = name_part.split('/')[1]
                        repo = name_part.split('/')[0]
                    else:
                        name = name_part
                        repo = 'unknown'
                    
                    version = parts[1] if len(parts) > 1 else ''
                    desc = lines[i+1].strip() if i+1 < len(lines) else 'No description'
                    
                    packages.append({
                        'name': name,
                        'version': version,
                        'source': 'pacman',
                        'repo': repo,
                        'desc': desc
                    })
            i += 1
        return packages
    except Exception as e:
        print(f"Pacman error: {e}")
        return []

def get_aur_packages(query):
    """Search AUR via Yay"""
    if not shutil.which("yay"):
        return []
    
    try:
        result = subprocess.run(['yay', '-Ss', query], capture_output=True, text=True, timeout=30)
        lines = result.stdout.split('\n')
        packages = []
        for line in lines:
            # Yay output: aur/name version
            if line.startswith('aur/'):
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].split('/')[1]
                    version = parts[1]
                    # Yay puts desc on same line sometimes or next, simplified parsing here
                    desc = ' '.join(parts[2:]) if len(parts) > 2 else 'AUR Package'
                    
                    packages.append({
                        'name': name,
                        'version': version,
                        'source': 'aur',
                        'repo': 'aur',
                        'desc': desc
                    })
        return packages
    except Exception as e:
        print(f"Yay error: {e}")
        return []

@app.route('/')
def index():
    # Serve the HTML file
    return send_from_directory('.', 'index.html')

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return jsonify([])
    
    # Run both searches
    pacman_pkgs = get_pacman_packages(query)
    aur_pkgs = get_aur_packages(query)
    
    # Combine and return
    return jsonify(pacman_pkgs + aur_pkgs)

if __name__ == '__main__':
    print("🌩️ StormOS Backend running on http://127.0.0.1:5000")
    # Run on localhost port 5000
    app.run(host='127.0.0.1', port=5000, debug=False)
