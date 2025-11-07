import os
import sqlite3
from contextlib import contextmanager
import hashlib
import json
import re
from urllib.parse import urlparse
from datetime import datetime


class Config:
    """Configuration class for the Spam Link Checker"""

    # Database Configuration
    DATABASE_PATH = "spam_checker.db"

    # Security Settings
    RATE_LIMIT_PER_MINUTE = 10
    MAX_URL_LENGTH = 2048
    CACHE_DURATION_HOURS = 24

    # Analysis Settings
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq',
                       '.xyz', '.top', '.club', '.loan', '.work', '.bid', '.win']
    SPAM_KEYWORDS = ['free', 'win', 'prize', 'bonus', 'offer', 'discount', 'click', 'secure', 'account',
                     'update', 'verify', 'confirm', 'login', 'password', 'banking', 'paypal', 'urgent',
                     'important', 'security', 'alert']
    URL_SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
                      'bit.do', 'shorte.st', 'bc.vc', 'adfly', 'click.ru', 'cutt.ly']

    # Risk Scoring
    RISK_WEIGHTS = {
        'url_length_very_long': 25,
        'url_length_long': 15,
        'suspicious_tld': 30,
        'ip_address': 35,
        'spam_keyword': 5,
        'excessive_subdomains': 20,
        'multiple_subdomains': 10,
        'url_shortener': 25,
        'special_characters': 10,
        'blacklisted': 100,
        'no_https': 5
    }

    # Thresholds
    HIGH_RISK_THRESHOLD = 80
    SUSPICIOUS_THRESHOLD = 50
    LOW_RISK_THRESHOLD = 25


class EnterpriseSpamDetector:
    def __init__(self):
        self.suspicious_tlds = Config.SUSPICIOUS_TLDS
        self.spam_keywords = Config.SPAM_KEYWORDS
        self.shorteners = Config.URL_SHORTENERS

    def get_url_hash(self, url: str) -> str:
        """Generate hash for URL for caching"""
        return hashlib.md5(url.encode('utf-8')).hexdigest()

    def check_cache(self, url_hash: str) -> dict:
        """Check if URL result is cached"""
        with DatabaseConfig.get_connection() as conn:
            result = conn.execute(
                "SELECT * FROM url_checks WHERE url_hash = ? AND updated_at > datetime('now', '-{} hours')".format(
                    Config.CACHE_DURATION_HOURS),
                (url_hash,)
            ).fetchone()
            if result:
                return dict(result)
        return None

    def save_to_cache(self, url_hash: str, result: dict):
        """Save result to cache"""
        with DatabaseConfig.get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO url_checks 
                (url_hash, url, risk_score, status, details, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                url_hash,
                result['url'],
                result['risk_score'],
                result['status'],
                json.dumps(result['details'])
            ))
            conn.commit()

    def is_blacklisted(self, domain: str) -> bool:
        """Check if domain is in blacklist"""
        with DatabaseConfig.get_connection() as conn:
            result = conn.execute(
                "SELECT 1 FROM blacklist WHERE domain = ?",
                (domain,)
            ).fetchone()
            return bool(result)

    def analyze_url_structure(self, url: str) -> dict:
        """Analyze URL structure for spam indicators"""
        parsed_url = urlparse(url)
        analysis = {
            'risk_score': 0,
            'details': [],
            'warnings': [],
            'domain': parsed_url.netloc
        }

        # Check URL length
        if len(url) > 100:
            analysis['risk_score'] += Config.RISK_WEIGHTS['url_length_very_long']
            analysis['details'].append(
                f"Very long URL ({len(url)} characters - often used to hide malicious content)")
        elif len(url) > 75:
            analysis['risk_score'] += Config.RISK_WEIGHTS['url_length_long']
            analysis['details'].append(f"Long URL ({len(url)} characters)")

        # Check suspicious TLDs
        if any(tld in parsed_url.netloc for tld in self.suspicious_tlds):
            analysis['risk_score'] += Config.RISK_WEIGHTS['suspicious_tld']
            analysis['details'].append(
                "Suspicious top-level domain (commonly used for spam)")

        # Check IP address in URL
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(parsed_url.netloc):
            analysis['risk_score'] += Config.RISK_WEIGHTS['ip_address']
            analysis['details'].append(
                "IP address used instead of domain name (common in phishing)")

        # Check suspicious keywords
        keyword_matches = [
            kw for kw in self.spam_keywords if kw in parsed_url.netloc.lower()]
        if keyword_matches:
            analysis['risk_score'] += len(keyword_matches) * \
                Config.RISK_WEIGHTS['spam_keyword']
            analysis['details'].append(
                f"Suspicious keywords detected: {', '.join(keyword_matches)}")

        # Check multiple subdomains
        subdomains = parsed_url.netloc.split('.')
        if len(subdomains) > 4:
            analysis['risk_score'] += Config.RISK_WEIGHTS['excessive_subdomains']
            analysis['details'].append(
                f"Excessive subdomains ({len(subdomains)}) - potential red flag")
        elif len(subdomains) > 3:
            analysis['risk_score'] += Config.RISK_WEIGHTS['multiple_subdomains']
            analysis['details'].append(
                f"Multiple subdomains ({len(subdomains)})")

        # Check URL shorteners
        if any(shortener in parsed_url.netloc for shortener in self.shorteners):
            analysis['risk_score'] += Config.RISK_WEIGHTS['url_shortener']
            analysis['details'].append(
                "URL shortening service detected (can hide malicious destinations)")

        # Check special characters
        if re.search(r'[^\w\.\-@]', parsed_url.netloc):
            analysis['risk_score'] += Config.RISK_WEIGHTS['special_characters']
            analysis['details'].append("Unusual characters in domain")

        # Check blacklist
        if self.is_blacklisted(parsed_url.netloc):
            analysis['risk_score'] = Config.RISK_WEIGHTS['blacklisted']
            analysis['details'].append("❌ Domain is blacklisted as known spam")

        # Check HTTPS
        if parsed_url.scheme != 'https':
            analysis['risk_score'] += Config.RISK_WEIGHTS['no_https']
            analysis['details'].append(
                "Website does not use HTTPS (less secure)")

        return analysis

    def check_spam_url(self, url: str, use_cache: bool = True) -> dict:
        """Main function to check if URL is spam"""
        try:
            url_hash = self.get_url_hash(url)

            # Check cache first
            if use_cache:
                cached_result = self.check_cache(url_hash)
                if cached_result:
                    cached_result['details'] = json.loads(
                        cached_result['details'])
                    cached_result['cached'] = True
                    return cached_result

            # Analyze URL
            analysis = self.analyze_url_structure(url)

            # Build result
            result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'risk_score': min(analysis['risk_score'], 100),
                'status': 'Unknown',
                'details': analysis['details'],
                'domain': analysis['domain'],
                'cached': False
            }

            # Determine status based on thresholds
            if result['risk_score'] >= Config.HIGH_RISK_THRESHOLD:
                result['status'] = 'High Risk'
            elif result['risk_score'] >= Config.SUSPICIOUS_THRESHOLD:
                result['status'] = 'Suspicious'
            elif result['risk_score'] >= Config.LOW_RISK_THRESHOLD:
                result['status'] = 'Low Risk'
            else:
                result['status'] = 'Likely Safe'

            # Save to cache
            if use_cache:
                self.save_to_cache(url_hash, result)

            return result

        except Exception as e:
            return {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'risk_score': 0,
                'status': 'Error',
                'details': [f"Error analyzing URL: {str(e)}"],
                'cached': False
            }


class DatabaseConfig:
    """Database configuration and utilities"""

    @staticmethod
    @contextmanager
    def get_connection():
        """Get database connection with context manager"""
        conn = sqlite3.connect(Config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def init_database():
        """Initialize database tables"""
        print(
            f"Initializing database at: {os.path.abspath(Config.DATABASE_PATH)}")

        with DatabaseConfig.get_connection() as conn:
            # URL checks table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS url_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_hash TEXT UNIQUE,
                    url TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Check history table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS check_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    risk_score INTEGER,
                    status TEXT,
                    user_session TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Blacklist table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    reason TEXT,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Pre-populate blacklist with known spam domains
            known_spam_domains = [
                ('free-prizes.tk', 'Known spam domain', 'System'),
                ('win-bonus.ga', 'Known spam domain', 'System'),
                ('secure-update.cf', 'Known spam domain', 'System'),
                ('account-verify.ml', 'Known phishing domain', 'System'),
                ('password-reset.ga', 'Known phishing domain', 'System'),
            ]

            for domain, reason, source in known_spam_domains:
                conn.execute('''
                    INSERT OR IGNORE INTO blacklist (domain, reason, source)
                    VALUES (?, ?, ?)
                ''', (domain, reason, source))

            # Create indexes
            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_url_checks_hash ON url_checks(url_hash)')
            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_history_session ON check_history(user_session)')
            conn.execute(
                'CREATE INDEX IF NOT EXISTS idx_blacklist_domain ON blacklist(domain)')

            conn.commit()

        print(f"Database initialized successfully!")

    @staticmethod
    def get_detector():
        """Get the spam detector instance"""
        return EnterpriseSpamDetector()


# Initialize database when this module is imported
DatabaseConfig.init_database()
