from flask import Flask, render_template, request, jsonify, session
import requests
import re
from urllib.parse import urlparse
import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta
from config import Config, DatabaseConfig

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Initialize detector
detector = DatabaseConfig.get_detector()


def init_session():
    """Initialize session variables"""
    if 'session_id' not in session:
        session['session_id'] = ''.join(secrets.choice(
            string.ascii_letters + string.digits) for _ in range(16))
    if 'check_count' not in session:
        session['check_count'] = 0
    if 'rate_limit_reset' not in session:
        session['rate_limit_reset'] = datetime.now().isoformat()


def check_rate_limit():
    """Check if user has exceeded rate limit"""
    now = datetime.now()
    reset_time = datetime.fromisoformat(session['rate_limit_reset'])

    if now > reset_time:
        session['check_count'] = 0
        session['rate_limit_reset'] = (now + timedelta(minutes=1)).isoformat()

    if session['check_count'] >= Config.RATE_LIMIT_PER_MINUTE:
        return False

    session['check_count'] += 1
    return True


def save_check_history(result):
    """Save check to history"""
    with DatabaseConfig.get_connection() as conn:
        conn.execute('''
            INSERT INTO check_history (url, risk_score, status, user_session)
            VALUES (?, ?, ?, ?)
        ''', (result['url'], result['risk_score'], result['status'], session['session_id']))
        conn.commit()


@app.route('/')
def index():
    """Home page"""
    init_session()
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_url():
    """Check URL endpoint"""
    init_session()

    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400

    # Check rate limit
    if not check_rate_limit():
        return jsonify({'error': 'Rate limit exceeded. Please wait a minute.'}), 429

    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Analyze URL
    result = detector.check_spam_url(url, use_cache=True)
    save_check_history(result)

    return jsonify(result)


@app.route('/history')
def get_history():
    """Get user's check history"""
    init_session()

    with DatabaseConfig.get_connection() as conn:
        recent_checks = conn.execute('''
            SELECT url, risk_score, status, created_at 
            FROM check_history 
            WHERE user_session = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        ''', (session['session_id'],)).fetchall()

    history = []
    for check in recent_checks:
        history.append({
            'url': check['url'],
            'risk_score': check['risk_score'],
            'status': check['status'],
            'created_at': check['created_at']
        })

    return jsonify(history)


@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear user's history"""
    init_session()

    with DatabaseConfig.get_connection() as conn:
        conn.execute('''
            DELETE FROM check_history WHERE user_session = ?
        ''', (session['session_id'],))
        conn.commit()

    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
