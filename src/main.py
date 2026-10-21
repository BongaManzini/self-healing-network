#!/usr/bin/env python3
"""
Self-Healing Network System - Main Application Entry Point.
Runs across Linux, Windows, and macOS with real-time network monitoring and Web Dashboard.
"""

import os
import sys
import platform
import logging

# Ensure project root directory is in sys.path so 'src' imports resolve regardless of cwd
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.config.settings import Settings
from src.api.routes import create_app
from src.utils.logger import setup_logging

def print_banner(config: Settings):
    banner = f"""
========================================================================
    🛡️  AEGIS: Self-Healing Network Defense & Monitor System
========================================================================
 [•] Operating System : {platform.system()} {platform.release()} ({platform.machine()})
 [•] Python Runtime   : {platform.python_version()}
 [•] Environment      : {config.ENVIRONMENT}
 [•] Web Dashboard    : http://{config.HOST if config.HOST != '0.0.0.0' else 'localhost'}:{config.PORT}/
 [•] REST API Index   : http://{config.HOST if config.HOST != '0.0.0.0' else 'localhost'}:{config.PORT}/api
 [•] Auto-Remediation : {'ENABLED (Sub-second Self-Healing)' if config.AUTO_REMEDIATE else 'DISABLED (Manual)'}
========================================================================
"""
    print(banner)

def main():
    """Main application entry point"""
    # Setup structured logging
    setup_logging()
    logger = logging.getLogger("SelfHealingNet")
    
    # Load configuration
    config = Settings()
    print_banner(config)
    
    # Create Flask application with Web Dashboard and APIs
    app = create_app(config)
    
    logger.info(f"Starting Self-Healing Network System on {config.HOST}:{config.PORT}")
    
    try:
        if config.ENVIRONMENT == "development":
            # use_reloader=False prevents duplicate background monitor threads
            app.run(host=config.HOST, port=config.PORT, debug=False, use_reloader=False)
        else:
            from waitress import serve
            serve(app, host=config.HOST, port=config.PORT)
    except KeyboardInterrupt:
        logger.info("Self-Healing Network System stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()