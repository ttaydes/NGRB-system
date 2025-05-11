from flask import Flask
from flask_socketio import SocketIO
from config import Config
from extensions import db
from routes.traffic import bp as traffic_bp
from routes.file import bp as file_bp
from routes.ai import bp as ai_bp
from routes.host import bp as host_bp
from routes.threat_intelligence import bp as threat_intelligence_bp
from routes.situation_awareness import bp as situation_awareness_bp
import threading
import time
from models.traffic import Traffic
from flask_cors import CORS
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app, resources=r'/*')

    # Initialize extensions
    db.init_app(app)
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Register blueprints
    app.register_blueprint(traffic_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(host_bp)
    app.register_blueprint(threat_intelligence_bp)
    app.register_blueprint(situation_awareness_bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app, socketio

app, socketio = create_app()

def background_traffic_update():
    """Background task to update traffic data"""
    with app.app_context():
        from models.traffic import Traffic
        while True:
            try:
                # Get latest traffic data
                latest_traffic = Traffic.query.order_by(Traffic.timestamp.desc()).first()
                if latest_traffic:
                    # 准备发送的数据
                    data = {
                        'alerts': get_alert_stats(),         # 获取告警统计
                        'attackTypes': get_attack_types(),   # 获取攻击类型分布
                        'timeline': get_attack_timeline(),   # 获取攻击时间线
                        
                    }
                    socketio.emit('security_update', data)
            except Exception as e:
                print(f"Error in background task: {e}")
            time.sleep(1)



def get_alert_stats():
    """获取告警统计"""
    with app.app_context():
        return {
            'low': Traffic.query.filter_by(risk_level='low').count(),
            'medium': Traffic.query.filter_by(risk_level='medium').count(),
            'high': Traffic.query.filter_by(risk_level='high').count()
        }

def get_attack_types():
    """获取攻击类型分布"""
    with app.app_context():
        from sqlalchemy import func
        result = db.session.query(
            Traffic.threat_type,
            func.count(Traffic.id)
        ).group_by(Traffic.threat_type).all()
        return dict(result)

def get_attack_timeline():
    """获取攻击时间线"""
    with app.app_context():
        from datetime import datetime, timedelta
        now = datetime.now()
        times = []
        values = []
        for i in range(8):
            time_point = now - timedelta(hours=i*3)
            count = Traffic.query.filter(
                Traffic.timestamp >= time_point - timedelta(hours=3),
                Traffic.timestamp < time_point
            ).count()
            times.insert(0, time_point.strftime('%H:00'))
            values.insert(0, count)
        return {'times': times, 'values': values}

# def get_geo_distribution():
#     """获取地理分布"""
#     with app.app_context():
#         from sqlalchemy import func
#         result = db.session.query(
#             Traffic.source_country,
#             func.count(Traffic.id)
#         ).group_by(Traffic.source_country).all()
#         return [{'name': country, 'value': count} for country, count in result if country]

if __name__ == '__main__':
    # Start background task
    thread = threading.Thread(target=background_traffic_update)
    thread.daemon = True
    thread.start()
    
    # Run the app
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)