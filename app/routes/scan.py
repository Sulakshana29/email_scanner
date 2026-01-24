"""
Scan Route - Email Analysis Endpoint

SECURITY:
- Only accepts .eml files
- Validates file type before processing
- Processes in memory only (no file persistence)
- All data is discarded after analysis
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any
import io

from app.services.parser import SafeEmailParser
from app.services.headers import HeaderAnalyzer
from app.services.urls import URLAnalyzer
from app.services.attachments import AttachmentAnalyzer
from app.services.scoring import ScoringEngine


router = APIRouter()


@router.post("/scan")
async def scan_email(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Scan an uploaded .eml file for phishing indicators.
    
    SECURITY MEASURES:
    - Only accepts .eml files
    - File is processed in memory only
    - No content is executed or rendered
    - No external requests are made
    - File data is discarded after analysis
    
    Args:
        file: Uploaded .eml file
        
    Returns:
        JSON report containing analysis results
        
    Raises:
        HTTPException: If file type is invalid or processing fails
    """
    
    # SECURITY: Validate file extension
    if not file.filename or not file.filename.lower().endswith('.eml'):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .eml files are accepted."
        )
    
    # SECURITY: Limit file size (10 MB max)
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    
    try:
        # Read file content into memory
        # SECURITY: Read entire file to check size
        file_content = await file.read()
        
        if len(file_content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.0f} MB."
            )
        
        # SECURITY: Validate it's actually email content (basic check)
        if not _is_valid_eml_content(file_content):
            raise HTTPException(
                status_code=400,
                detail="File does not appear to be a valid .eml file."
            )
        
        # Parse email safely
        parser = SafeEmailParser(file_content)
        email_data = parser.get_full_analysis()
        
        # Analyze headers
        header_analyzer = HeaderAnalyzer(email_data['headers'])
        header_analysis = header_analyzer.analyze()
        
        # Analyze URLs in body
        url_analyzer = URLAnalyzer(email_data['body'])
        url_analysis = url_analyzer.analyze()
        
        # Analyze attachments
        attachment_analyzer = AttachmentAnalyzer(email_data['attachments'])
        attachment_analysis = attachment_analyzer.analyze()
        
        # Calculate risk score
        scoring_engine = ScoringEngine()
        scoring_result = scoring_engine.calculate_score(
            header_analysis,
            url_analysis,
            attachment_analysis
        )
        
        # Build comprehensive report
        report = {
            'filename': file.filename,
            'verdict': scoring_result['verdict'],
            'score': scoring_result['score'],
            'risk_summary': scoring_result['risk_summary'],
            'scoring_reasons': scoring_result['reasons'],
            
            # Header information
            'headers': {
                'from': header_analysis['from_address'],
                'from_name': header_analysis['from_name'],
                'to': email_data['headers'].get('to', ''),
                'subject': email_data['headers'].get('subject', ''),
                'date': email_data['headers'].get('date', ''),
                'message_id': email_data['headers'].get('message_id', ''),
                'reply_to': header_analysis['reply_to_address'],
                'return_path': header_analysis['return_path'],
            },
            
            # Domain analysis
            'domains': {
                'from_domain': header_analysis['from_domain'],
                'reply_to_domain': header_analysis['reply_to_domain'],
                'return_path_domain': header_analysis['return_path_domain'],
                'mismatches': header_analysis['mismatches'],
            },
            
            # Authentication results
            'authentication': header_analysis['authentication'],
            
            # Received chain info
            'received_chain': {
                'hop_count': header_analysis['received_hops']['hop_count'],
                'first_hops': header_analysis['received_hops']['headers'][:3],
            },
            
            # URL analysis
            'urls': {
                'count': url_analysis['url_count'],
                'urls': url_analysis['urls'],
            },
            
            # Attachment analysis
            'attachments': {
                'count': attachment_analysis['attachment_count'],
                'attachments': attachment_analysis['attachments'],
            },
            
            # All issues combined
            'all_issues': _combine_issues(
                header_analysis.get('issues', []),
                url_analysis.get('issues', []),
                attachment_analysis.get('issues', [])
            ),
        }
        
        # SECURITY: Clear sensitive data from memory
        del file_content
        del email_data
        
        return report
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except Exception as e:
        # Log error but don't expose internal details
        # In production, use proper logging
        print(f"Error processing email: {str(e)}")
        
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the email. The file may be corrupted."
        )


def _is_valid_eml_content(content: bytes) -> bool:
    """
    Perform basic validation that content is an email file.
    
    SECURITY: Basic sanity check to prevent processing non-email files.
    
    Args:
        content: File content as bytes
        
    Returns:
        True if content appears to be valid email format
    """
    try:
        # Try to decode as text
        text = content.decode('utf-8', errors='ignore')
        
        # Check for common email headers
        # At minimum, an email should have some header structure
        required_indicators = [
            ':',  # Headers have colons
        ]
        
        # Should have at least one common email header
        common_headers = [
            'From:', 'To:', 'Subject:', 'Date:',
            'Message-ID:', 'MIME-Version:', 'Content-Type:'
        ]
        
        has_header = any(header.lower() in text.lower() for header in common_headers)
        has_colon = ':' in text[:1000]  # Check first 1000 chars
        
        return has_header and has_colon
        
    except Exception:
        return False


def _combine_issues(
    header_issues: list,
    url_issues: list,
    attachment_issues: list
) -> list:
    """
    Combine all issues from different analyzers.
    
    Args:
        header_issues: Issues from header analysis
        url_issues: Issues from URL analysis
        attachment_issues: Issues from attachment analysis
        
    Returns:
        Combined list of all issues
    """
    all_issues = []
    
    all_issues.extend(header_issues)
    all_issues.extend(url_issues)
    all_issues.extend(attachment_issues)
    
    # Sort by severity
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    all_issues.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 3))
    
    return all_issues
