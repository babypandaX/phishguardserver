from flask import Flask, request, jsonify
from flask_cors import CORS
import tldextract
import requests
import whois
import ssl
import socket
import re
import logging
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib3 import PoolManager
from urllib3.exceptions import SSLError
from whois.parser import PywhoisError
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from textdistance import levenshtein
import dns.resolver

# Configuration from environment variables
config = {
    "host": "0.0.0.0",
    "port": int(os.environ.get("PORT", 5000)),
    "debug": os.environ.get("DEBUG", "false").lower() == "true",
    "user_agent": os.environ.get("USER_AGENT", "PhishGuard/2.0"),
    "google_api_key": os.environ.get("GOOGLE_API_KEY", ""),
    "risk_threshold": int(os.environ.get("RISK_THRESHOLD", 80)),
    "log_level": os.environ.get("LOG_LEVEL", "INFO")
}

# Set up logging
logging.basicConfig(level=config["log_level"])
logger = logging.getLogger(__name__)

# Suppress noisy library logs
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('tldextract').setLevel(logging.CRITICAL)

app = Flask(__name__)
CORS(app, resources={r"/check": {"origins": "*"}})

# Load brand database
try:
    with open('brands.json') as f:
        brand_db = json.load(f)
        brand_keywords = sum(brand_db.values(), [])
except Exception as e:
    logger.error(f"Error loading brands database: {str(e)}")
    brand_keywords = []

EV_OIDS = [
    cryptography.x509.ObjectIdentifier("2.23.140.1.1"),
    cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.34697.2.1"),
    cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.17326.10.14.2.1.2"),
]

class TLSAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        self.poolmanager = PoolManager(
            ssl_context=ctx,
            num_pools=connections,
            maxsize=maxsize,
            block=block
        )

def is_typosquatting(domain):
    """Enhanced brand detection with substring matching"""
    # Split domain into meaningful parts
    domain_parts = re.split(r'[\d\-_]+', domain)  # Split on numbers/dashes
    
    # Check each part against brands
    for part in domain_parts:
        if len(part) < 3:  # Ignore short fragments
            continue
        for brand in brand_keywords:
            if brand in part.lower():
                return True
            if levenshtein(part.lower(), brand) <= 2:
                return True
    
    # Check regex patterns
    patterns = [
        fr'\b({"|".join(brand_keywords)})[aeiou]{{0,2}}(s|z)?\d*[-_]?(\b|$)',
        r'(.)\1{3}',  # Quadruple character repetition
        r'[-_]{2,}',  # Multiple consecutive special chars
        r'\d+[a-z]+\d+',  # Number-letter sandwiches
        r'(web3|defi|nft|crypto)[-_]',  # Crypto-related keywords
        r'(login|verify|account|secure|wallet|auth|exchange)[-.]',  # Auth keywords
        r'[a-z]{8,}\d{3,}',  # Long strings with numbers
        r'(app|service|platform)-?v\d+'  # Versioning patterns
    ]
    return any(re.search(p, domain, re.IGNORECASE) for p in patterns)

def check_ssl(url):
    """Verify SSL/TLS connection validity"""
    try:
        if not url.startswith('https://'):
            return {'valid': True, 'error_type': None}

        session = requests.Session()
        session.mount('https://', TLSAdapter())
        response = session.get(
            url,
            timeout=8,
            headers={'User-Agent': config['user_agent']},
            allow_redirects=True,
            stream=False
        )
        return {'valid': True, 'error_type': None}
    except Exception as e:
        return {'valid': False, 'error_type': str(e)}

def get_certificate_info(domain):
    """Retrieve SSL certificate details - simplified version"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Only check if certificate exists
                return {'valid': True}
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def check_domain_age(domain):
    """Check domain registration details with improved error handling"""
    try:
        info = whois.whois(domain)
        
        # Check if domain exists
        if not info.domain_name:
            return {'age': None, 'exists': False}
            
        # Handle creation date
        created = info.creation_date
        if not created:
            return {'age': None, 'exists': True}
            
        if isinstance(created, list):
            created = created[0]
            
        if not isinstance(created, datetime):
            return {'age': None, 'exists': True}
            
        return {
            'age': (datetime.now() - created).days,
            'exists': True
        }
        
    except PywhoisError:
        # Domain doesn't exist in WHOIS
        return {'age': None, 'exists': False}
    except Exception as e:
        logger.error(f"Domain age error for {domain}: {str(e)}")
        return {'age': None, 'exists': None}

def check_safe_browsing(url):
    """Check Google Safe Browsing API"""
    if not config['google_api_key']:
        logger.warning("Google API key missing - skipping Safe Browsing check")
        return False
        
    try:
        response = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": config['google_api_key']},
            json={
                "client": {"clientId": "phishguard", "clientVersion": "2.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=8
        )
        
        if response.status_code != 200:
            logger.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
            return False
            
        return bool(response.json().get('matches'))
    except Exception as e:
        logger.error(f"Safe Browsing error: {str(e)}")
        return False

def resolve_dns(domain):
    """Resolve domain with retries and fallback"""
    try:
        # Try A record first
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.resolver.Timeout:
        logger.warning(f"DNS resolution timeout for {domain}")
    except Exception as e:
        logger.warning(f"DNS resolution error for {domain}: {str(e)}")
    
    try:
        # Try CNAME record if A record failed
        answers = dns.resolver.resolve(domain, 'CNAME')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception as e:
        logger.warning(f"DNS resolution error for {domain}: {str(e)}")
        return False

def analyze_url(url):
    """Main analysis function with improved scoring"""
    try:
        logger.info(f"Analyzing URL: {url}")
        parsed = tldextract.extract(url)
        full_domain = f"{parsed.domain}.{parsed.suffix}"
        risk_score = 0
        flags = []

        with ThreadPoolExecutor(max_workers=4) as executor:
            # DNS resolution check with better handling
            dns_resolved = resolve_dns(full_domain)
            if not dns_resolved:
                flags.append("DNS Resolution Failed")
                risk_score += 5  # Reduced penalty

            # Concurrent checks
            domain_future = executor.submit(check_domain_age, full_domain)
            google_future = executor.submit(check_safe_browsing, url)
            
            # Typosquatting detection
            if is_typosquatting(full_domain):
                flags.append("Typosquatting Patterns Detected")
                risk_score += 30

            # Domain registration check
            try:
                domain_data = domain_future.result(timeout=10)
                if domain_data['exists'] is False:
                    flags.append("Unregistered Domain")
                    risk_score += 20
                elif domain_data['age'] is not None:
                    if domain_data['age'] < 7:
                        flags.append("Very New Domain (<7 days)")
                        risk_score += 15
                    elif domain_data['age'] < 90:
                        flags.append("New Domain (<90 days)")
                        risk_score += 10
            except TimeoutError:
                logger.warning("Domain age check timed out")
            
            # Number pattern detection
            if re.search(r'\d{3,}[a-z-]+\d{3,}', full_domain):
                flags.append("Suspicious Number Pattern")
                risk_score += 20

            # Safe Browsing check
            try:
                safe_browsing_match = google_future.result(timeout=10)
                if safe_browsing_match:
                    flags.append("Known Phishing Site")
                    risk_score = 100  # Override only if confirmed
            except TimeoutError:
                logger.warning("Safe Browsing check timed out")

            # SSL checks only if DNS resolved and not already high risk
            if dns_resolved and risk_score < 100:
                ssl_future = executor.submit(check_ssl, url)
                
                try:
                    ssl_result = ssl_future.result(timeout=6)
                    if not ssl_result['valid']:
                        risk_score += 10
                        flags.append(f"SSL Error: {ssl_result.get('error_type', 'Unknown')}")
                except TimeoutError:
                    logger.warning("SSL check timed out")

        # Final score calculation
        final_score = min(100, risk_score)
        
        # High risk threshold
        if final_score >= config['risk_threshold'] and not any("Known Phishing Site" in flag for flag in flags):
            flags.append("High Risk Phishing Suspected")
            
        logger.info(f"Final risk score: {final_score}, Flags: {flags}")
        return {
            "risk_score": final_score,
            "flags": [f for f in flags if f],
            "analyzed_url": url
        }

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}", exc_info=True)
        return {
            "risk_score": 0,  # Return 0 instead of 100 to avoid false positives
            "flags": ["Temporary analysis failure"],
            "analyzed_url": url
        }

@app.route('/check', methods=['POST'])
def check_url():
    """Main API endpoint"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request"}), 400
            
        if not isinstance(data['url'], str) or len(data['url']) > 2048:
            return jsonify({"error": "Invalid URL format"}), 400
            
        return jsonify(analyze_url(data['url']))
        
    except Exception as e:
        logger.error(f"Endpoint error: {str(e)}", exc_info=True)
        return jsonify({"error": "Server processing error"}), 500

if __name__ == '__main__':
    app.run(
        host=config['host'],
        port=config['port'],
        threaded=True,
        debug=config['debug']
    )
