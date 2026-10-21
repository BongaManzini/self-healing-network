from flask import Flask
from src.api.endpoints.anomaly import anomaly_bp
from src.api.endpoints.actions import actions_bp
from src.config.settings import Settings

def create_app(config: Settings) -> Flask:
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config.from_object(config)
    
    # Register blueprints
    app.register_blueprint(anomaly_bp, url_prefix='/api/anomaly')
    app.register_blueprint(actions_bp, url_prefix='/api/actions')
    
    # Add basic health check endpoint
    @app.route('/health')
    def health_check():
        return {
            "status": "healthy",
            "service": "self-healing-network",
            "timestamp": datetime.now().isoformat()
        }
    
    @app.route('/')
    def index():
        return {
            "message": "Self-Healing Network System API",
            "version": "1.0.0",
            "endpoints": {
                "anomaly_detection": "/api/anomaly/detect",
                "actions": "/api/actions/status",
                "health": "/health"
            }
        }
    
    return app