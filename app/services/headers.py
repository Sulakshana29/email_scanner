"""
Header Analysis Service

Analyzes email headers for suspicious patterns and authentication issues.
"""

from typing import Dict, List, Any
import re
from email.utils import parseaddr


class HeaderAnalyzer:
    """
    Analyze email headers for phishing indicators.
    """
    
    def __init__(self, headers: Dict[str, Any]):
        """
        Initialize analyzer with email headers.
        
        Args:
            headers: Dictionary of email headers from parser
        """
        self.headers = headers
        self.issues = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform complete header analysis.
        
        Returns:
            Dictionary containing analysis results and issues found
        """
        self.issues = []
        
        # Extract key information
        from_header = self.headers.get('from', '')
        reply_to = self.headers.get('reply_to', '')
        return_path = self.headers.get('return_path', '')
        
        # Parse email addresses
        from_name, from_email = parseaddr(from_header)
        reply_to_name, reply_to_email = parseaddr(reply_to) if reply_to else ('', '')
        return_path_email = self._extract_email(return_path)
        
        # Get domains
        from_domain = self._extract_domain(from_email)
        reply_to_domain = self._extract_domain(reply_to_email)
        return_path_domain = self._extract_domain(return_path_email)
        
        # Check for mismatches
        mismatches = self._check_mismatches(
            from_domain, 
            reply_to_domain, 
            return_path_domain
        )
        
        # Analyze authentication results
        auth_analysis = self._analyze_authentication()
        
        # Analyze received headers
        received_analysis = self._analyze_received_chain()
        
        # Check for suspicious patterns in headers
        suspicious_patterns = self._check_suspicious_patterns()
        
        return {
            'from_address': from_email,
            'from_name': from_name,
            'from_domain': from_domain,
            'reply_to_address': reply_to_email,
            'reply_to_domain': reply_to_domain,
            'return_path': return_path_email,
            'return_path_domain': return_path_domain,
            'mismatches': mismatches,
            'authentication': auth_analysis,
            'received_hops': received_analysis,
            'suspicious_patterns': suspicious_patterns,
            'issues': self.issues
        }
    
    def _extract_email(self, address: str) -> str:
        """
        Extract email address from string.
        
        Args:
            address: Email address string (may include angle brackets)
            
        Returns:
            Clean email address
        """
        if not address:
            return ''
        
        # Remove angle brackets if present
        match = re.search(r'<(.+?)>', address)
        if match:
            return match.group(1).strip()
        return address.strip()
    
    def _extract_domain(self, email: str) -> str:
        """
        Extract domain from email address.
        
        Args:
            email: Email address
            
        Returns:
            Domain part of email
        """
        if not email or '@' not in email:
            return ''
        
        return email.split('@')[-1].lower()
    
    def _check_mismatches(
        self, 
        from_domain: str, 
        reply_to_domain: str, 
        return_path_domain: str
    ) -> Dict[str, Any]:
        """
        Check for domain mismatches between From, Reply-To, and Return-Path.
        
        SECURITY: Domain mismatches are a common phishing indicator.
        
        Args:
            from_domain: Domain from From header
            reply_to_domain: Domain from Reply-To header
            return_path_domain: Domain from Return-Path header
            
        Returns:
            Dictionary of mismatch findings
        """
        mismatches = {
            'from_vs_reply_to': False,
            'from_vs_return_path': False
        }
        
        # Check From vs Reply-To
        if reply_to_domain and from_domain != reply_to_domain:
            mismatches['from_vs_reply_to'] = True
            self.issues.append({
                'type': 'DOMAIN_MISMATCH',
                'severity': 'MEDIUM',
                'description': f'From domain ({from_domain}) differs from Reply-To domain ({reply_to_domain})',
                'impact': 'Replies may go to different address than shown sender'
            })
        
        # Check From vs Return-Path
        if return_path_domain and from_domain != return_path_domain:
            mismatches['from_vs_return_path'] = True
            self.issues.append({
                'type': 'DOMAIN_MISMATCH',
                'severity': 'MEDIUM',
                'description': f'From domain ({from_domain}) differs from Return-Path domain ({return_path_domain})',
                'impact': 'Bounces may go to different address than shown sender'
            })
        
        return mismatches
    
    def _analyze_authentication(self) -> Dict[str, Any]:
        """
        Analyze email authentication results (SPF, DKIM, DMARC).
        
        Returns:
            Dictionary of authentication results
        """
        auth_results = {
            'spf': 'NOT_CHECKED',
            'dkim': 'NOT_CHECKED',
            'dmarc': 'NOT_CHECKED',
            'raw': self.headers.get('authentication_results', '')
        }
        
        auth_header = self.headers.get('authentication_results', '').lower()
        spf_header = self.headers.get('received_spf', '').lower()
        
        # Parse SPF
        if 'spf=pass' in auth_header or 'pass' in spf_header:
            auth_results['spf'] = 'PASS'
        elif 'spf=fail' in auth_header or 'fail' in spf_header:
            auth_results['spf'] = 'FAIL'
            self.issues.append({
                'type': 'AUTH_FAILURE',
                'severity': 'HIGH',
                'description': 'SPF authentication failed',
                'impact': 'Sender may be spoofing the From domain'
            })
        elif 'spf=' in auth_header:
            auth_results['spf'] = 'CHECKED'
        
        # Parse DKIM
        if 'dkim=pass' in auth_header:
            auth_results['dkim'] = 'PASS'
        elif 'dkim=fail' in auth_header:
            auth_results['dkim'] = 'FAIL'
            self.issues.append({
                'type': 'AUTH_FAILURE',
                'severity': 'HIGH',
                'description': 'DKIM signature verification failed',
                'impact': 'Email may have been modified or sender is not authorized'
            })
        elif 'dkim=' in auth_header:
            auth_results['dkim'] = 'CHECKED'
        
        # Parse DMARC
        if 'dmarc=pass' in auth_header:
            auth_results['dmarc'] = 'PASS'
        elif 'dmarc=fail' in auth_header:
            auth_results['dmarc'] = 'FAIL'
            self.issues.append({
                'type': 'AUTH_FAILURE',
                'severity': 'HIGH',
                'description': 'DMARC policy check failed',
                'impact': 'Email fails domain alignment checks'
            })
        elif 'dmarc=' in auth_header:
            auth_results['dmarc'] = 'CHECKED'
        
        return auth_results
    
    def _analyze_received_chain(self) -> Dict[str, Any]:
        """
        Analyze the Received header chain.
        
        Returns:
            Dictionary with received chain analysis
        """
        received_chain = self.headers.get('received_chain', [])
        
        return {
            'hop_count': len(received_chain),
            'headers': received_chain[:5]  # Include first 5 hops for inspection
        }
    
    def _check_suspicious_patterns(self) -> List[Dict[str, str]]:
        """
        Check for suspicious patterns in headers.
        
        Returns:
            List of suspicious patterns found
        """
        patterns = []
        
        subject = self.headers.get('subject', '').lower()
        from_header = self.headers.get('from', '').lower()
        
        # Check for common phishing keywords in subject
        phishing_keywords = [
            'urgent', 'verify', 'suspend', 'confirm', 'account',
            'security', 'unusual', 'click here', 'update', 'expire'
        ]
        
        for keyword in phishing_keywords:
            if keyword in subject:
                patterns.append({
                    'pattern': f'Suspicious keyword in subject: {keyword}',
                    'location': 'Subject header'
                })
        
        # Check for suspicious from patterns
        if re.search(r'\d{4,}', from_header):  # Long number sequences
            patterns.append({
                'pattern': 'Long number sequence in From address',
                'location': 'From header'
            })
        
        # Check for multiple consecutive dots (rare in legitimate emails)
        if '..' in from_header:
            patterns.append({
                'pattern': 'Multiple consecutive dots in From address',
                'location': 'From header'
            })
        
        return patterns
