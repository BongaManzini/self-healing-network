"""
Flask application factory and primary route definitions for Self-Healing Network.
"""

import os
from datetime import datetime
from flask import Flask, render_template, jsonify
from src.api.endpoints.anomaly import anomaly_bp
from src.api.endpoints.actions import actions_bp
from src.api.endpoints.monitor import monitor_bp
from src.config.settings import Settings

def create_app(config: Settings = None) -> Flask:
    """Create and configure the Flask application with Web Dashboard and API routes"""
    config = config or Settings()
    
    # Calculate absolute paths for web templates and static assets
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, 'web', 'templates')
    static_dir = os.path.join(base_dir, 'web', 'static')
    
    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )
    app.config.from_object(config)
    
    # Register blueprints
    app.register_blueprint(anomaly_bp, url_prefix='/api/anomaly')
    app.register_blueprint(actions_bp, url_prefix='/api/actions')
    app.register_blueprint(monitor_bp, url_prefix='/api/monitor')
    
    # Web Dashboard Alternative
    @app.route('/')
    @app.route('/dashboard')
    def dashboard():
        """Render the interactive cyber-defense web dashboard"""
        return render_template('dashboard.html')

    # Basic health check endpoint
    @app.route('/health')
    def health_check():
        return {
            "status": "healthy",
            "service": "self-healing-network",
            "timestamp": datetime.now().isoformat()
        }
    
    # API Directory endpoint
    @app.route('/api')
    def api_index():
        return {
            "name": "Self-Healing Network System API",
            "version": "2.0.0",
            "cross_platform": ["Linux", "Windows", "macOS"],
            "endpoints": {
                "web_dashboard": "/",
                "anomaly_detect": "POST /api/anomaly/detect",
                "anomaly_simulate": "POST /api/anomaly/simulate/<anomaly_type>",
                "anomaly_incidents": "GET /api/anomaly/incidents",
                "anomaly_audit": "GET /api/anomaly/audit",
                "monitor_summary": "GET /api/monitor/summary",
                "monitor_interfaces": "GET /api/monitor/interfaces",
                "monitor_connections": "GET /api/monitor/connections",
                "toggle_auto_heal": "POST /api/monitor/toggle-auto-heal",
                "actions_block_ip": "POST /api/actions/block-ip",
                "actions_unblock_ip": "POST /api/actions/unblock-ip",
                "actions_isolate_device": "POST /api/actions/isolate-device",
                "actions_restore_device": "POST /api/actions/restore-device",
                "actions_flush_dns": "POST /api/actions/flush-dns",
                "actions_heal_arp": "POST /api/actions/heal-arp",
                "actions_terminate_process": "POST /api/actions/terminate-process",
                "actions_status": "GET /api/actions/status",
                "health": "GET /health"
            }
        }
    
    return app