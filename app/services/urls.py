"""
URL Analysis Service

Safely extract and analyze URLs from email content without fetching them.

SECURITY: Does NOT fetch URLs, follow redirects, or make any network requests.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse


class URLAnalyzer:
    """
    Analyze URLs found in email body for phishing indicators.
    """
    
    # Common URL shortener domains
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'short.io', 'rebrand.ly', 'cutt.ly', 'tiny.cc',
        'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
    }
    
    def __init__(self, email_body: str):
        """
        Initialize analyzer with email body text.
        
        Args:
            email_body: Plain text email body
        """
        self.email_body = email_body
        self.issues = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform complete URL analysis.
        
        Returns:
            Dictionary containing URLs and analysis results
        """
        self.issues = []
        
        # Extract URLs using regex (safe - no network calls)
        urls = self._extract_urls()
        
        # Analyze each URL
        analyzed_urls = []
        for url in urls:
            analysis = self._analyze_url(url)
            analyzed_urls.append(analysis)
        
        return {
            'url_count': len(urls),
            'urls': analyzed_urls,
            'issues': self.issues
        }
    
    def _extract_urls(self) -> List[str]:
        """
        Extract URLs from email body using regex.
        
        SECURITY: Only uses regex pattern matching, no network requests.
        
        Returns:
            List of URL strings found in email body
        """
        # Regex pattern to match URLs
        # Matches http://, https://, and www. URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        urls = re.findall(url_pattern, self.email_body, re.IGNORECASE)
        
        # Also find www. URLs without protocol
        www_pattern = r'www\.[^\s<>"{}|\\^`\[\]]+'
        www_urls = re.findall(www_pattern, self.email_body, re.IGNORECASE)
        
        # Combine and deduplicate
        all_urls = list(set(urls + www_urls))
        
        return all_urls
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL for suspicious characteristics.
        
        SECURITY: No network requests, only local analysis.
        
        Args:
            url: URL string to analyze
            
        Returns:
            Dictionary containing URL analysis
        """
        analysis = {
            'url': url,
            'flags': [],
            'risk_level': 'LOW'
        }
        
        # Parse URL (safe - no network call)
        try:
            # Add scheme if missing for parsing
            parse_url = url if url.startswith(('http://', 'https://')) else f'http://{url}'
            parsed = urlparse(parse_url)
            
            domain = parsed.netloc or parsed.path.split('/')[0]
            analysis['domain'] = domain
            analysis['scheme'] = parsed.scheme
            
            # Check for IP-based URLs (suspicious)
            if self._is_ip_address(domain):
                analysis['flags'].append('IP_ADDRESS_URL')
                analysis['risk_level'] = 'HIGH'
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'HIGH',
                    'description': f'URL uses IP address instead of domain: {url}',
                    'impact': 'IP-based URLs are uncommon in legitimate emails'
                })
            
            # Check for URL shorteners
            if self._is_url_shortener(domain):
                analysis['flags'].append('URL_SHORTENER')
                analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'MEDIUM',
                    'description': f'URL shortener detected: {domain}',
                    'impact': 'Shortened URLs hide the true destination'
                })
            
            # Check for punycode (internationalized domain names)
            if 'xn--' in domain:
                analysis['flags'].append('PUNYCODE_DOMAIN')
                analysis['risk_level'] = 'HIGH'
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'HIGH',
                    'description': f'Punycode domain detected: {domain}',
                    'impact': 'May be homograph attack using lookalike characters'
                })
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                analysis['flags'].append('SUSPICIOUS_TLD')
                analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'MEDIUM',
                    'description': f'Suspicious TLD in URL: {url}',
                    'impact': 'Some TLDs are commonly used in phishing'
                })
            
            # Check for excessive subdomains (possible obfuscation)
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                analysis['flags'].append('EXCESSIVE_SUBDOMAINS')
                analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'MEDIUM',
                    'description': f'URL has excessive subdomains: {domain}',
                    'impact': 'May be attempting to obfuscate true domain'
                })
            
            # Check for suspicious port numbers
            if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
                analysis['flags'].append('UNCOMMON_PORT')
                analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'MEDIUM',
                    'description': f'Uncommon port number: {parsed.port} in {url}',
                    'impact': 'Non-standard ports may indicate suspicious service'
                })
            
            # Check for authentication in URL (username:password@domain)
            if '@' in parsed.netloc and parsed.netloc.index('@') > 0:
                analysis['flags'].append('AUTH_IN_URL')
                analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
                self.issues.append({
                    'type': 'SUSPICIOUS_URL',
                    'severity': 'MEDIUM',
                    'description': f'URL contains authentication credentials: {url}',
                    'impact': 'May be obfuscating the true domain'
                })
            
        except Exception as e:
            analysis['flags'].append('PARSE_ERROR')
            analysis['error'] = str(e)
        
        return analysis
    
    def _is_ip_address(self, domain: str) -> bool:
        """
        Check if domain is an IP address.
        
        Args:
            domain: Domain string
            
        Returns:
            True if domain is an IP address
        """
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Simple IPv4 pattern check
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ipv4_pattern, domain):
            # Validate octets are in range 0-255
            octets = domain.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        
        # Check for IPv6 (simplified - just look for colons)
        if ':' in domain and domain.count(':') >= 2:
            return True
        
        return False
    
    def _is_url_shortener(self, domain: str) -> bool:
        """
        Check if domain is a known URL shortener.
        
        Args:
            domain: Domain string
            
        Returns:
            True if domain is a known shortener
        """
        # Remove port if present
        domain = domain.split(':')[0].lower()
        
        # Check against known shorteners
        return domain in self.URL_SHORTENERS or \
               any(domain.endswith(f'.{shortener}') for shortener in self.URL_SHORTENERS)
