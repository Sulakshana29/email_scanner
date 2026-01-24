"""
Safe Email Parser Service

SECURITY PRINCIPLES:
- Uses Python's built-in email library (RFC 822 / MIME compliant)
- Does NOT execute, render, or fetch any content
- Does NOT open attachments
- Processes data in memory only
- Extracts metadata and text content safely
"""

import email
from email import policy
from email.message import EmailMessage
from typing import Dict, Any, List, Optional
import hashlib


class SafeEmailParser:
    """
    Safely parse .eml files without executing or rendering content.
    """
    
    def __init__(self, eml_content: bytes):
        """
        Initialize parser with email content.
        
        Args:
            eml_content: Raw .eml file content as bytes
        """
        # SECURITY: Use default policy which doesn't execute anything
        self.message: EmailMessage = email.message_from_bytes(
            eml_content,
            policy=policy.default
        )
    
    def get_headers(self) -> Dict[str, Any]:
        """
        Extract email headers safely.
        
        Returns:
            Dictionary containing header information
        """
        headers = {}
        
        # Extract standard headers (safe - just string values)
        headers['from'] = self.message.get('From', '')
        headers['to'] = self.message.get('To', '')
        headers['subject'] = self.message.get('Subject', '')
        headers['date'] = self.message.get('Date', '')
        headers['message_id'] = self.message.get('Message-ID', '')
        headers['reply_to'] = self.message.get('Reply-To', '')
        headers['return_path'] = self.message.get('Return-Path', '')
        
        # Extract authentication results if present
        headers['authentication_results'] = self.message.get('Authentication-Results', '')
        headers['received_spf'] = self.message.get('Received-SPF', '')
        
        # Extract full Received header chain (important for tracking)
        # SECURITY: get_all returns list of header values, doesn't execute anything
        received_headers = self.message.get_all('Received', [])
        headers['received_chain'] = received_headers
        
        # Extract all headers for detailed analysis
        headers['all_headers'] = dict(self.message.items())
        
        return headers
    
    def get_text_body(self) -> str:
        """
        Extract plain text body ONLY.
        
        SECURITY: Does NOT extract HTML to prevent any rendering vulnerabilities.
        
        Returns:
            Plain text content of email body
        """
        text_content = []
        
        # Walk through message parts
        if self.message.is_multipart():
            for part in self.message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                # SECURITY: Only extract text/plain, ignore HTML and other types
                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    try:
                        # get_content() safely decodes the content
                        payload = part.get_content()
                        if isinstance(payload, str):
                            text_content.append(payload)
                    except Exception:
                        # Skip parts that can't be decoded safely
                        continue
        else:
            # Single part message
            if self.message.get_content_type() == 'text/plain':
                try:
                    payload = self.message.get_content()
                    if isinstance(payload, str):
                        text_content.append(payload)
                except Exception:
                    pass
        
        return '\n\n'.join(text_content)
    
    def get_attachments_metadata(self) -> List[Dict[str, Any]]:
        """
        Extract attachment metadata WITHOUT opening or executing them.
        
        SECURITY:
        - Does NOT open attachments
        - Does NOT execute attachment content
        - Only extracts metadata (filename, type, size, hash)
        
        Returns:
            List of dictionaries containing attachment metadata
        """
        attachments = []
        
        if self.message.is_multipart():
            for part in self.message.walk():
                content_disposition = str(part.get('Content-Disposition', ''))
                
                # Check if this part is an attachment
                if 'attachment' in content_disposition or part.get_filename():
                    attachment_info = {}
                    
                    # Extract filename (safe - just metadata)
                    filename = part.get_filename()
                    attachment_info['filename'] = filename if filename else 'unknown'
                    
                    # Extract MIME type (safe - just metadata)
                    attachment_info['content_type'] = part.get_content_type()
                    
                    # Get payload as bytes to calculate size and hash
                    # SECURITY: get_payload returns raw data, doesn't execute it
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            # Calculate size
                            attachment_info['size_bytes'] = len(payload)
                            
                            # Calculate SHA-256 hash (useful for threat intelligence)
                            # SECURITY: Only computing hash, not executing content
                            sha256_hash = hashlib.sha256(payload).hexdigest()
                            attachment_info['sha256'] = sha256_hash
                        else:
                            attachment_info['size_bytes'] = 0
                            attachment_info['sha256'] = ''
                    except Exception:
                        attachment_info['size_bytes'] = 0
                        attachment_info['sha256'] = ''
                    
                    attachments.append(attachment_info)
        
        return attachments
    
    def get_full_analysis(self) -> Dict[str, Any]:
        """
        Get complete email analysis data.
        
        Returns:
            Dictionary containing all parsed data
        """
        return {
            'headers': self.get_headers(),
            'body': self.get_text_body(),
            'attachments': self.get_attachments_metadata()
        }
