import streamlit as st
import requests
import re
from urllib.parse import urlparse
import time
import pandas as pd
from datetime import datetime, timedelta
import hashlib
import json
import secrets
import string

# Import our configuration
from config import Config, DatabaseConfig

# Configure the page
st.set_page_config(
    page_title="Enterprise Spam Link Checker",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: 700;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
        padding: 1.5rem;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
    }
    .safe-card {
        background: linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%);
    }
    .warning-card {
        background: linear-gradient(135deg, #f7971e 0%, #ffd200 100%);
    }
    .danger-card {
        background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
    }
    .info-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
    }
    .stat-number {
        font-size: 2rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .stat-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
    .url-display {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 5px;
        border-left: 4px solid #1f77b4;
        margin: 1rem 0;
        word-break: break-all;
    }
</style>
""", unsafe_allow_html=True)

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
                "SELECT * FROM url_checks WHERE url_hash = ? AND updated_at > datetime('now', '-{} hours')".format(Config.CACHE_DURATION_HOURS),
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
            analysis['details'].append(f"Very long URL ({len(url)} characters - often used to hide malicious content)")
        elif len(url) > 75:
            analysis['risk_score'] += Config.RISK_WEIGHTS['url_length_long']
            analysis['details'].append(f"Long URL ({len(url)} characters)")
        
        # Check suspicious TLDs
        if any(tld in parsed_url.netloc for tld in self.suspicious_tlds):
            analysis['risk_score'] += Config.RISK_WEIGHTS['suspicious_tld']
            analysis['details'].append("Suspicious top-level domain (commonly used for spam)")
        
        # Check IP address in URL
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(parsed_url.netloc):
            analysis['risk_score'] += Config.RISK_WEIGHTS['ip_address']
            analysis['details'].append("IP address used instead of domain name (common in phishing)")
        
        # Check suspicious keywords
        keyword_matches = [kw for kw in self.spam_keywords if kw in parsed_url.netloc.lower()]
        if keyword_matches:
            analysis['risk_score'] += len(keyword_matches) * Config.RISK_WEIGHTS['spam_keyword']
            analysis['details'].append(f"Suspicious keywords detected: {', '.join(keyword_matches)}")
        
        # Check multiple subdomains
        subdomains = parsed_url.netloc.split('.')
        if len(subdomains) > 4:
            analysis['risk_score'] += Config.RISK_WEIGHTS['excessive_subdomains']
            analysis['details'].append(f"Excessive subdomains ({len(subdomains)}) - potential red flag")
        elif len(subdomains) > 3:
            analysis['risk_score'] += Config.RISK_WEIGHTS['multiple_subdomains']
            analysis['details'].append(f"Multiple subdomains ({len(subdomains)})")
        
        # Check URL shorteners
        if any(shortener in parsed_url.netloc for shortener in self.shorteners):
            analysis['risk_score'] += Config.RISK_WEIGHTS['url_shortener']
            analysis['details'].append("URL shortening service detected (can hide malicious destinations)")
        
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
            analysis['details'].append("Website does not use HTTPS (less secure)")
        
        return analysis
    
    def check_spam_url(self, url: str, use_cache: bool = True) -> dict:
        """Main function to check if URL is spam"""
        try:
            url_hash = self.get_url_hash(url)
            
            # Check cache first
            if use_cache:
                cached_result = self.check_cache(url_hash)
                if cached_result:
                    cached_result['details'] = json.loads(cached_result['details'])
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

# Initialize detector
detector = EnterpriseSpamDetector()

# Session state management
def init_session_state():
    if 'session_id' not in st.session_state:
        st.session_state.session_id = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    if 'check_count' not in st.session_state:
        st.session_state.check_count = 0
    if 'rate_limit_reset' not in st.session_state:
        st.session_state.rate_limit_reset = datetime.now()

def check_rate_limit():
    """Check if user has exceeded rate limit"""
    now = datetime.now()
    if now > st.session_state.rate_limit_reset:
        st.session_state.check_count = 0
        st.session_state.rate_limit_reset = now + timedelta(minutes=1)
    
    if st.session_state.check_count >= Config.RATE_LIMIT_PER_MINUTE:
        st.error(f"Rate limit exceeded. Please wait {60 - (now - st.session_state.rate_limit_reset + timedelta(minutes=1)).seconds} seconds.")
        return False
    
    st.session_state.check_count += 1
    return True

def save_check_history(result: dict):
    """Save check to history"""
    with DatabaseConfig.get_connection() as conn:
        conn.execute('''
            INSERT INTO check_history (url, risk_score, status, user_session)
            VALUES (?, ?, ?, ?)
        ''', (result['url'], result['risk_score'], result['status'], st.session_state.session_id))
        conn.commit()

# Initialize session
init_session_state()

# Main application
st.markdown('<h1 class="main-header">🔍 Enterprise Spam Link Checker</h1>', unsafe_allow_html=True)

# Sidebar for additional features
with st.sidebar:
    st.header("⚙️ Settings & Tools")
    
    use_cache = st.checkbox("Use Caching", value=True, help="Faster results for previously checked URLs")
    show_technical = st.checkbox("Show Technical Details", value=False)
    
    st.header("📊 Statistics")
    with DatabaseConfig.get_connection() as conn:
        total_checks = conn.execute("SELECT COUNT(*) FROM check_history").fetchone()[0]
        today_checks = conn.execute(
            "SELECT COUNT(*) FROM check_history WHERE created_at > datetime('now', '-1 day')"
        ).fetchone()[0]
    
    st.metric("Total Checks", total_checks)
    st.metric("Checks Today", today_checks)
    
    st.header("🛡️ Safety Tips")
    st.info("""
    - Always check URLs before clicking
    - Look for HTTPS in legitimate sites
    - Be wary of too-good-to-be-true offers
    - Use unique passwords for different sites
    """)

# Main content area
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("🔍 URL Analysis")
    
    # URL input form
    with st.form("url_check_form"):
        url_input = st.text_input("Enter URL to check:", 
                                placeholder="https://example.com",
                                help="Enter full URL including http:// or https://")
        
        submitted = st.form_submit_button("Check URL")
        
        if submitted:
            if url_input:
                if not check_rate_limit():
                    st.stop()
                
                # Validate URL format
                if not url_input.startswith(('http://', 'https://')):
                    url_input = 'https://' + url_input
                
                # Show progress
                with st.spinner('Analyzing URL...'):
                    result = detector.check_spam_url(url_input, use_cache)
                    save_check_history(result)
                
                # Display results
                st.markdown("---")
                st.subheader("📊 Analysis Results")
                
                # Display the checked URL
                st.markdown(f"""
                <div class="url-display">
                    <strong>Checked URL:</strong><br>
                    {result['url']}
                </div>
                """, unsafe_allow_html=True)
                
                # Risk indicator with colored card
                risk_color = "safe-card" if result['status'] in ['Likely Safe', 'Low Risk'] else "warning-card" if result['status'] == 'Suspicious' else "danger-card"
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown(f"""
                    <div class="metric-card {risk_color}">
                        <div class="stat-number">{result['status']}</div>
                        <div class="stat-label">Status</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="stat-number">{result['risk_score']}/100</div>
                        <div class="stat-label">Risk Score</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="stat-number">{len(result['details'])}</div>
                        <div class="stat-label">Issues Found</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Details
                st.subheader("🔍 Detailed Analysis")
                for detail in result['details']:
                    if "blacklisted" in detail.lower() or "❌" in detail:
                        st.error(f"🚫 {detail}")
                    elif "suspicious" in detail.lower() or "risk" in detail.lower():
                        st.warning(f"⚠️ {detail}")
                    else:
                        st.info(f"ℹ️ {detail}")
                
                # Recommendations
                st.subheader("💡 Recommendations")
                if result['status'] == 'High Risk':
                    st.error("""
                    🚨 **CRITICAL WARNING**: This URL appears to be highly risky!
                    
                    **Immediate Actions:**
                    - ❌ Avoid clicking on this link
                    - ❌ Do not enter any personal information
                    - 📧 Report to your IT security team
                    - 🗑️ Delete the message containing this link
                    """)
                elif result['status'] == 'Suspicious':
                    st.warning("""
                    ⚠️ **CAUTION**: This URL shows suspicious characteristics
                    
                    **Recommended Actions:**
                    - 🔍 Verify the source before clicking
                    - 🌐 Use a VPN if you must visit
                    - 📱 Access from a secure device
                    - 🔒 Don't enter sensitive information
                    """)
                elif result['status'] == 'Low Risk':
                    st.info("""
                    ℹ️ **LOW RISK**: Some minor concerns detected
                    
                    **Safety Tips:**
                    - ✅ Generally safe but be cautious
                    - 🔒 Check for HTTPS encryption
                    - 🌟 Verify website reputation
                    - 👀 Look for trust indicators
                    """)
                else:
                    st.success("""
                    ✅ **SAFE**: This URL appears to be legitimate
                    
                    **Best Practices:**
                    - 👍 No major security concerns detected
                    - 🔒 Standard precautions still recommended
                    - 👁️ Always be vigilant online
                    - 📚 Keep security software updated
                    """)
            
            else:
                st.error("Please enter a URL to check.")

with col2:
    st.subheader("📋 Recent Checks")
    
    with DatabaseConfig.get_connection() as conn:
        recent_checks = conn.execute('''
            SELECT url, risk_score, status, created_at 
            FROM check_history 
            WHERE user_session = ? 
            ORDER BY created_at DESC 
            LIMIT 5
        ''', (st.session_state.session_id,)).fetchall()
    
    if recent_checks:
        for check in recent_checks:
            status_color = {
                'Likely Safe': '#28a745',
                'Low Risk': '#20c997', 
                'Suspicious': '#ffc107',
                'High Risk': '#dc3545',
                'Error': '#6c757d'
            }.get(check['status'], '#007bff')
            
            # Truncate URL for display
            display_url = check['url'][:30] + '...' if len(check['url']) > 30 else check['url']
            
            st.markdown(f"""
            <div style="border-left: 4px solid {status_color}; padding: 0.8rem; margin: 0.5rem 0; background: #f8f9fa; border-radius: 0 5px 5px 0;">
                <div style="font-size: 0.7rem; color: #666; margin-bottom: 0.3rem;">{check['created_at'][:16]}</div>
                <div style="font-weight: bold; font-size: 0.8rem; margin-bottom: 0.3rem;">{display_url}</div>
                <div style="font-size: 0.8rem;">
                    Score: <strong>{check['risk_score']}/100</strong><br>
                    Status: <strong style="color: {status_color}">{check['status']}</strong>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No recent checks. Start by checking a URL!")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #6c757d; padding: 2rem;'>
        <h3>🛡️ Enterprise Spam Link Checker</h3>
        <p>Version 2.0 • Built with Streamlit</p>
    </div>
    """, 
    unsafe_allow_html=True
)