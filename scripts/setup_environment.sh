#!/bin/bash

echo "Setting up Self-Healing Network System environment..."

# Create necessary directories
mkdir -p data/logs
mkdir -p data/backups
mkdir -p data/pcap_storage

# Check if Python virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Set execute permissions on scripts
chmod +x scripts/*.sh

echo "Environment setup complete!"
echo "To start the application:"
echo "source venv/bin/activate && python src/main.py"