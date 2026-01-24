"""
FastAPI Email Phishing Scanner - Main Application

SECURITY DESIGN:
- Processes files in memory only (no persistent storage)
- Accepts only .eml files
- Does not execute, render, or fetch any content
- All processing is local and safe
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
from pathlib import Path

# Import routes
from app.routes import scan

# Create FastAPI application
app = FastAPI(
    title="Email Phishing Scanner",
    description="Secure email phishing analysis tool - processes .eml files safely without execution",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS (adjust for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/api", tags=["scanning"])

# Serve static files and templates
templates_dir = Path(__file__).parent.parent / "templates"


@app.get("/", response_class=HTMLResponse)
async def root():
    """
    Serve the main web UI.
    
    Returns:
        HTML response with the scanner interface
    """
    index_file = templates_dir / "index.html"
    
    if index_file.exists():
        return index_file.read_text(encoding='utf-8')
    else:
        return """
        <html>
            <head><title>Email Scanner</title></head>
            <body>
                <h1>Email Phishing Scanner</h1>
                <p>Template file not found. Please ensure templates/index.html exists.</p>
            </body>
        </html>
        """


@app.get("/api/health")
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        Status information
    """
    return {
        "status": "healthy",
        "service": "Email Phishing Scanner",
        "version": "1.0.0"
    }


@app.get("/favicon.ico")
async def favicon():
    """
    Return a simple favicon to prevent 404 errors in browser logs.
    
    Returns:
        Empty response with appropriate content type
    """
    # Return empty 204 No Content to stop browser requests
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    # SECURITY: Only bind to localhost by default
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,  # Disable in production
        log_level="info"
    )
