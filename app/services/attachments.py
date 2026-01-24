"""
Attachment Analysis Service

Analyzes email attachments WITHOUT opening or executing them.

SECURITY:
- Does NOT open attachments
- Does NOT execute attachment content
- Does NOT extract embedded content
- Only analyzes metadata (filename, type, size, hash)
"""

from typing import List, Dict, Any
import re


class AttachmentAnalyzer:
    """
    Analyze email attachments for risk indicators using metadata only.
    """
    
    # High-risk file extensions that can execute code
    HIGH_RISK_EXTENSIONS = {
        '.exe', '.com', '.bat', '.cmd', '.scr', '.pif',  # Windows executables
        '.js', '.jse', '.vbs', '.vbe', '.wsf', '.wsh',   # Scripts
        '.msi', '.msp', '.msc',                           # Installers
        '.hta', '.cpl', '.jar',                           # Applications
        '.lnk', '.url',                                   # Shortcuts
        '.ps1', '.psm1',                                  # PowerShell
        '.reg',                                            # Registry files
        '.application', '.gadget',                         # .NET/Windows
        '.inf', '.ins', '.isp',                            # Installation files
    }
    
    # Medium-risk extensions (macros enabled)
    MEDIUM_RISK_EXTENSIONS = {
        '.docm', '.dotm', '.xlsm', '.xltm', '.xlam',      # Office with macros
        '.pptm', '.potm', '.ppam', '.ppsm',               # PowerPoint with macros
        '.sldm',                                           # Slide with macros
        '.pdf',                                            # PDF (can contain JS)
        '.rtf',                                            # Rich text (exploits possible)
    }
    
    # Archive extensions (can hide malware)
    ARCHIVE_EXTENSIONS = {
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        '.iso', '.img', '.vhd', '.vmdk',                   # Disk images
        '.cab', '.msi',                                    # Installers/cabinets
    }
    
    def __init__(self, attachments: List[Dict[str, Any]]):
        """
        Initialize analyzer with attachment metadata.
        
        Args:
            attachments: List of attachment metadata dictionaries
        """
        self.attachments = attachments
        self.issues = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform complete attachment analysis.
        
        Returns:
            Dictionary containing analysis results
        """
        self.issues = []
        
        analyzed_attachments = []
        
        for attachment in self.attachments:
            analysis = self._analyze_attachment(attachment)
            analyzed_attachments.append(analysis)
        
        return {
            'attachment_count': len(self.attachments),
            'attachments': analyzed_attachments,
            'issues': self.issues
        }
    
    def _analyze_attachment(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single attachment for risk indicators.
        
        SECURITY: Only analyzes metadata, never opens the file.
        
        Args:
            attachment: Attachment metadata dictionary
            
        Returns:
            Dictionary containing attachment analysis
        """
        filename = attachment.get('filename', 'unknown')
        content_type = attachment.get('content_type', 'unknown')
        size = attachment.get('size_bytes', 0)
        file_hash = attachment.get('sha256', '')
        
        analysis = {
            'filename': filename,
            'content_type': content_type,
            'size_bytes': size,
            'size_readable': self._format_size(size),
            'sha256': file_hash,
            'flags': [],
            'risk_level': 'LOW'
        }
        
        # Extract file extension
        extension = self._get_extension(filename)
        analysis['extension'] = extension
        
        # Check for high-risk extensions
        if extension.lower() in self.HIGH_RISK_EXTENSIONS:
            analysis['flags'].append('HIGH_RISK_EXTENSION')
            analysis['risk_level'] = 'HIGH'
            self.issues.append({
                'type': 'DANGEROUS_ATTACHMENT',
                'severity': 'HIGH',
                'description': f'Attachment has executable extension: {filename}',
                'impact': 'File can execute code if opened'
            })
        
        # Check for medium-risk extensions
        elif extension.lower() in self.MEDIUM_RISK_EXTENSIONS:
            analysis['flags'].append('MEDIUM_RISK_EXTENSION')
            analysis['risk_level'] = 'MEDIUM'
            self.issues.append({
                'type': 'RISKY_ATTACHMENT',
                'severity': 'MEDIUM',
                'description': f'Attachment may contain macros: {filename}',
                'impact': 'Macros can execute malicious code'
            })
        
        # Check for archive extensions
        if extension.lower() in self.ARCHIVE_EXTENSIONS:
            analysis['flags'].append('ARCHIVE_FILE')
            if analysis['risk_level'] == 'LOW':
                analysis['risk_level'] = 'MEDIUM'
            self.issues.append({
                'type': 'ARCHIVE_ATTACHMENT',
                'severity': 'MEDIUM',
                'description': f'Attachment is an archive: {filename}',
                'impact': 'Archives can hide malicious files'
            })
        
        # Check for double extensions (e.g., invoice.pdf.exe)
        if self._has_double_extension(filename):
            analysis['flags'].append('DOUBLE_EXTENSION')
            analysis['risk_level'] = 'HIGH'
            self.issues.append({
                'type': 'DANGEROUS_ATTACHMENT',
                'severity': 'HIGH',
                'description': f'Attachment has double extension: {filename}',
                'impact': 'Common obfuscation technique to hide true file type'
            })
        
        # Check for misleading content type
        if self._is_misleading_content_type(extension, content_type):
            analysis['flags'].append('MISLEADING_CONTENT_TYPE')
            analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
            self.issues.append({
                'type': 'SUSPICIOUS_ATTACHMENT',
                'severity': 'MEDIUM',
                'description': f'Content-Type mismatch: {content_type} for {filename}',
                'impact': 'File extension does not match declared type'
            })
        
        # Check for suspicious filename patterns
        suspicious_patterns = self._check_filename_patterns(filename)
        if suspicious_patterns:
            analysis['flags'].extend(suspicious_patterns)
            analysis['risk_level'] = 'MEDIUM' if analysis['risk_level'] == 'LOW' else analysis['risk_level']
        
        # Check for unusually large attachments
        if size > 10 * 1024 * 1024:  # 10 MB
            analysis['flags'].append('LARGE_FILE')
            self.issues.append({
                'type': 'SUSPICIOUS_ATTACHMENT',
                'severity': 'LOW',
                'description': f'Large attachment: {filename} ({self._format_size(size)})',
                'impact': 'Unusually large file size'
            })
        
        return analysis
    
    def _get_extension(self, filename: str) -> str:
        """
        Extract file extension from filename.
        
        Args:
            filename: Filename string
            
        Returns:
            File extension including the dot
        """
        if '.' not in filename:
            return ''
        
        return '.' + filename.rsplit('.', 1)[-1]
    
    def _has_double_extension(self, filename: str) -> bool:
        """
        Check if filename has double extension (e.g., file.pdf.exe).
        
        SECURITY: Double extensions are a common phishing technique.
        
        Args:
            filename: Filename string
            
        Returns:
            True if double extension detected
        """
        # Common safe extensions that might appear before real extension
        safe_extensions = {'.tar', '.min', '.backup', '.old', '.bak'}
        
        parts = filename.split('.')
        if len(parts) < 3:
            return False
        
        # Get last two extensions
        second_last_ext = '.' + parts[-2].lower()
        
        # Check if second-to-last extension looks like a file type
        document_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.rtf', '.jpg', '.jpeg', '.png', '.gif'
        }
        
        # If second extension is a document type, it's suspicious
        if second_last_ext in document_extensions:
            return True
        
        # If second extension is not a known safe extension, flag it
        if second_last_ext not in safe_extensions:
            # Check if it looks like a file extension (not just part of filename)
            if len(parts[-2]) <= 5 and parts[-2].isalnum():
                return True
        
        return False
    
    def _is_misleading_content_type(self, extension: str, content_type: str) -> bool:
        """
        Check if content type doesn't match file extension.
        
        Args:
            extension: File extension
            content_type: MIME content type
            
        Returns:
            True if mismatch detected
        """
        # Common extension to content-type mappings
        expected_types = {
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.zip': 'application/zip',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.txt': 'text/plain',
        }
        
        extension = extension.lower()
        if extension in expected_types:
            expected = expected_types[extension]
            if content_type and expected not in content_type:
                return True
        
        return False
    
    def _check_filename_patterns(self, filename: str) -> List[str]:
        """
        Check for suspicious patterns in filename.
        
        Args:
            filename: Filename string
            
        Returns:
            List of pattern flags found
        """
        flags = []
        
        # Check for multiple spaces (obfuscation)
        if '  ' in filename:
            flags.append('MULTIPLE_SPACES')
        
        # Check for unusual characters
        if re.search(r'[^\w\s\-\.\(\)_]', filename):
            flags.append('UNUSUAL_CHARACTERS')
        
        # Check for very long filename
        if len(filename) > 100:
            flags.append('LONG_FILENAME')
        
        # Check for common phishing filename patterns
        phishing_patterns = [
            r'invoice.*\d+',
            r'payment.*\d+',
            r'receipt.*\d+',
            r'urgent',
            r'confidential',
            r'secure.*document'
        ]
        
        for pattern in phishing_patterns:
            if re.search(pattern, filename.lower()):
                flags.append('PHISHING_FILENAME_PATTERN')
                self.issues.append({
                    'type': 'SUSPICIOUS_ATTACHMENT',
                    'severity': 'MEDIUM',
                    'description': f'Suspicious filename pattern: {filename}',
                    'impact': 'Filename matches common phishing patterns'
                })
                break
        
        return flags
    
    def _format_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format.
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
