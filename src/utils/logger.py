import logging
import os
from datetime import datetime

def setup_logging():
    """Setup application logging"""
    log_dir = "data/logs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"self_healing_{datetime.now().strftime('%Y%m%d')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def get_logger(name):
    """Get a logger instance"""
    return logging.getLogger(name)