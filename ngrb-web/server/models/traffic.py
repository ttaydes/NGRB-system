from datetime import datetime
from extensions import db
import base64

class Traffic(db.Model):
    __tablename__ = 'traffic'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    source_ip = db.Column(db.String(45))  # Support for IPv6
    source_port = db.Column(db.Integer)
    destination_ip = db.Column(db.String(45))  # Support for IPv6
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    packet_size = db.Column(db.Integer)
    payload = db.Column(db.Text)  # Store base64 encoded payload
    risk_level = db.Column(db.String(10))
    threat_type = db.Column(db.String(50))
    status = db.Column(db.String(20))

    def __init__(self, **kwargs):
        # 处理 payload
        raw_payload = kwargs.pop('payload', None)
        if raw_payload:
            if isinstance(raw_payload, bytes):
                # 存储原始二进制数据
                self.payload_binary = raw_payload
                # 存储 base64 编码的文本版本
                self.payload = base64.b64encode(raw_payload).decode('utf-8')
            elif isinstance(raw_payload, str):
                # 如果是字符串，直接存储
                self.payload = raw_payload
                try:
                    # 尝试解码 base64 字符串
                    self.payload_binary = base64.b64decode(raw_payload)
                except:
                    # 如果不是 base64 编码，则存储为 None
                    self.payload_binary = None
        super(Traffic, self).__init__(**kwargs)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'payload': self.payload,  # base64 encoded text
            'risk_level': self.risk_level,
            'threat_type': self.threat_type,
            'status': self.status
        }