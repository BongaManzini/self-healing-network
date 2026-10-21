#!/usr/bin/env python3
"""
Self-Healing Network System - Main Application
"""

import logging
from src.config.settings import Settings
from src.api.routes import create_app
from src.utils.logger import setup_logging

def main():
    """Main application entry point"""
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config = Settings()
    
    # Create Flask application
    app = create_app(config)
    
    logger.info("Starting Self-Healing Network System")
    
    # Start the application
    if config.ENVIRONMENT == "development":
        app.run(host=config.HOST, port=config.PORT, debug=True)
    else:
        from waitress import serve
        serve(app, host=config.HOST, port=config.PORT)

if __name__ == "__main__":
    main()