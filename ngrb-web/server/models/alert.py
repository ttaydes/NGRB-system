from extensions import db
from datetime import datetime

class Alert(db.Model):
    """告警模型"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(50))  # 告警类型：流量告警、文件告警、主机告警等
    source = db.Column(db.String(100))  # 告警来源：IP地址、文件名、主机名等
    description = db.Column(db.Text)  # 告警描述
    risk_level = db.Column(db.String(20))  # 风险等级：high、medium、low
    status = db.Column(db.String(20), default='unhandled')  # 处理状态：unhandled、handling、resolved
    details = db.Column(db.JSON)  # 详细信息，JSON格式
    
    def __repr__(self):
        return f'<Alert {self.id}: {self.type} - {self.risk_level}>'
    
    def to_dict(self):
        """转换为字典格式"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'type': self.type,
            'source': self.source,
            'description': self.description,
            'risk_level': self.risk_level,
            'status': self.status,
            'details': self.details
        } 