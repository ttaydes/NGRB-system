from datetime import datetime
from extensions import db

class Host(db.Model):
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(45), nullable=False)  # Support for IPv6
    os = db.Column(db.String(100))
    status = db.Column(db.String(20), default='unknown')
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    last_seen = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip': self.ip,
            'os': self.os,
            'status': self.status,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'alerts': self.get_recent_alerts()
        }
    
    def get_recent_alerts(self):
        # 这里可以添加获取最近告警的逻辑
        # 示例数据
        return [
            {
                'level': 'high',
                'message': '检测到可疑进程',
                'timestamp': datetime.now().isoformat()
            },
            {
                'level': 'medium',
                'message': 'CPU使用率过高',
                'timestamp': datetime.now().isoformat()
            }
        ]