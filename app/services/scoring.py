"""
Scoring Engine Service

Rule-based risk scoring system with explainable results.
"""

from typing import Dict, Any, List


class ScoringEngine:
    """
    Calculate risk score based on analysis findings.
    
    Score ranges:
    - 0-30: LOW risk
    - 31-60: MEDIUM risk
    - 61-100: HIGH risk
    """
    
    def __init__(self):
        """Initialize scoring engine."""
        self.score = 0
        self.reasons = []
        self.max_score = 100
    
    def calculate_score(
        self,
        header_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate overall risk score based on all analyses.
        
        Args:
            header_analysis: Results from header analysis
            url_analysis: Results from URL analysis
            attachment_analysis: Results from attachment analysis
            
        Returns:
            Dictionary containing score, verdict, and detailed reasons
        """
        self.score = 0
        self.reasons = []
        
        # Score header issues
        self._score_headers(header_analysis)
        
        # Score URL issues
        self._score_urls(url_analysis)
        
        # Score attachment issues
        self._score_attachments(attachment_analysis)
        
        # Ensure score doesn't exceed maximum
        self.score = min(self.score, self.max_score)
        
        # Determine verdict
        verdict = self._get_verdict(self.score)
        
        # Get risk summary
        risk_summary = self._get_risk_summary()
        
        return {
            'score': self.score,
            'verdict': verdict,
            'reasons': self.reasons,
            'risk_summary': risk_summary
        }
    
    def _score_headers(self, header_analysis: Dict[str, Any]):
        """
        Score header-related issues.
        
        Args:
            header_analysis: Header analysis results
        """
        # Domain mismatches
        mismatches = header_analysis.get('mismatches', {})
        
        if mismatches.get('from_vs_reply_to'):
            self.score += 15
            self.reasons.append({
                'category': 'Header Analysis',
                'issue': 'From and Reply-To domains differ',
                'points': 15,
                'explanation': 'Replies will go to a different domain than the apparent sender'
            })
        
        if mismatches.get('from_vs_return_path'):
            self.score += 10
            self.reasons.append({
                'category': 'Header Analysis',
                'issue': 'From and Return-Path domains differ',
                'points': 10,
                'explanation': 'Bounce messages will go to a different domain than the apparent sender'
            })
        
        # Authentication failures
        auth = header_analysis.get('authentication', {})
        
        if auth.get('spf') == 'FAIL':
            self.score += 20
            self.reasons.append({
                'category': 'Authentication',
                'issue': 'SPF check failed',
                'points': 20,
                'explanation': 'Sender is not authorized to send from this domain'
            })
        
        if auth.get('dkim') == 'FAIL':
            self.score += 20
            self.reasons.append({
                'category': 'Authentication',
                'issue': 'DKIM verification failed',
                'points': 20,
                'explanation': 'Email signature verification failed - message may be forged or modified'
            })
        
        if auth.get('dmarc') == 'FAIL':
            self.score += 15
            self.reasons.append({
                'category': 'Authentication',
                'issue': 'DMARC check failed',
                'points': 15,
                'explanation': 'Email fails domain alignment policy'
            })
        
        # Suspicious patterns in headers
        patterns = header_analysis.get('suspicious_patterns', [])
        if patterns:
            pattern_score = min(len(patterns) * 3, 15)
            self.score += pattern_score
            pattern_list = [p['pattern'] for p in patterns[:3]]
            self.reasons.append({
                'category': 'Header Analysis',
                'issue': f'Suspicious patterns detected: {", ".join(pattern_list)}',
                'points': pattern_score,
                'explanation': 'Headers contain patterns commonly seen in phishing emails'
            })
    
    def _score_urls(self, url_analysis: Dict[str, Any]):
        """
        Score URL-related issues.
        
        Args:
            url_analysis: URL analysis results
        """
        urls = url_analysis.get('urls', [])
        
        # Track highest risk URL issues
        has_ip_url = False
        has_shortener = False
        has_punycode = False
        suspicious_url_count = 0
        
        for url in urls:
            flags = url.get('flags', [])
            
            if 'IP_ADDRESS_URL' in flags:
                has_ip_url = True
            if 'URL_SHORTENER' in flags:
                has_shortener = True
            if 'PUNYCODE_DOMAIN' in flags:
                has_punycode = True
            if url.get('risk_level') in ['MEDIUM', 'HIGH']:
                suspicious_url_count += 1
        
        # Score based on findings
        if has_ip_url:
            self.score += 25
            self.reasons.append({
                'category': 'URL Analysis',
                'issue': 'URL with IP address detected',
                'points': 25,
                'explanation': 'Legitimate services rarely use IP addresses in URLs'
            })
        
        if has_punycode:
            self.score += 20
            self.reasons.append({
                'category': 'URL Analysis',
                'issue': 'Punycode (internationalized) domain detected',
                'points': 20,
                'explanation': 'May be a homograph attack using lookalike characters'
            })
        
        if has_shortener:
            self.score += 10
            self.reasons.append({
                'category': 'URL Analysis',
                'issue': 'URL shortener detected',
                'points': 10,
                'explanation': 'Shortened URLs hide the true destination'
            })
        
        if suspicious_url_count > 0 and not (has_ip_url or has_punycode or has_shortener):
            url_score = min(suspicious_url_count * 5, 15)
            self.score += url_score
            self.reasons.append({
                'category': 'URL Analysis',
                'issue': f'{suspicious_url_count} suspicious URL(s) found',
                'points': url_score,
                'explanation': 'URLs contain suspicious characteristics'
            })
    
    def _score_attachments(self, attachment_analysis: Dict[str, Any]):
        """
        Score attachment-related issues.
        
        Args:
            attachment_analysis: Attachment analysis results
        """
        attachments = attachment_analysis.get('attachments', [])
        
        # Track highest risk attachment issues
        has_executable = False
        has_double_ext = False
        has_macro_doc = False
        has_archive = False
        
        for attachment in attachments:
            flags = attachment.get('flags', [])
            risk_level = attachment.get('risk_level', 'LOW')
            
            if 'HIGH_RISK_EXTENSION' in flags or risk_level == 'HIGH':
                has_executable = True
            if 'DOUBLE_EXTENSION' in flags:
                has_double_ext = True
            if 'MEDIUM_RISK_EXTENSION' in flags:
                has_macro_doc = True
            if 'ARCHIVE_FILE' in flags:
                has_archive = True
        
        # Score based on findings
        if has_double_ext:
            self.score += 30
            self.reasons.append({
                'category': 'Attachment Analysis',
                'issue': 'Attachment with double extension detected',
                'points': 30,
                'explanation': 'Double extensions are used to disguise malicious files'
            })
        
        if has_executable:
            self.score += 25
            self.reasons.append({
                'category': 'Attachment Analysis',
                'issue': 'Executable attachment detected',
                'points': 25,
                'explanation': 'Attachment can execute code - extremely dangerous'
            })
        
        if has_macro_doc:
            self.score += 15
            self.reasons.append({
                'category': 'Attachment Analysis',
                'issue': 'Document with macros detected',
                'points': 15,
                'explanation': 'Macros can be used to execute malicious code'
            })
        
        if has_archive and not has_executable:
            self.score += 8
            self.reasons.append({
                'category': 'Attachment Analysis',
                'issue': 'Archive attachment detected',
                'points': 8,
                'explanation': 'Archives can hide malicious files and bypass filters'
            })
    
    def _get_verdict(self, score: int) -> str:
        """
        Determine verdict based on score.
        
        Args:
            score: Calculated risk score
            
        Returns:
            Verdict string (LOW, MEDIUM, or HIGH)
        """
        if score <= 30:
            return 'LOW'
        elif score <= 60:
            return 'MEDIUM'
        else:
            return 'HIGH'
    
    def _get_risk_summary(self) -> str:
        """
        Generate human-readable risk summary.
        
        Returns:
            Risk summary string
        """
        if self.score <= 30:
            return 'This email shows minimal signs of phishing. However, always verify unexpected requests.'
        elif self.score <= 60:
            return 'This email shows concerning indicators. Exercise caution and verify sender identity before taking any action.'
        else:
            return 'This email shows strong indicators of phishing. Do not click links, open attachments, or provide information.'
    
    def get_detailed_report(self) -> Dict[str, Any]:
        """
        Generate detailed scoring report.
        
        Returns:
            Detailed report dictionary
        """
        return {
            'total_score': self.score,
            'max_score': self.max_score,
            'verdict': self._get_verdict(self.score),
            'reasons': self.reasons,
            'reason_count': len(self.reasons),
            'risk_summary': self._get_risk_summary()
        }
