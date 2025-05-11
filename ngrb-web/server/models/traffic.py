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
    response_code = db.Column(db.Integer)
    payload = db.Column(db.Text)  # Store base64 encoded payload
    header_body = db.Column(db.Text)  # 新增header体字段
    risk_level = db.Column(db.String(10))
    traffic_type = db.Column(db.String(50))
    threat_type = db.Column(db.String(50))
    packet_type = db.Column(db.String(10))

    def __init__(self, **kwargs):
        # 处理 payload 和 header_body
        raw_payload = kwargs.pop('payload', None)
        raw_header = kwargs.pop('header_body', None)
        
        if raw_payload:
            if isinstance(raw_payload, bytes):
                self.payload_binary = raw_payload
                self.payload = base64.b64encode(raw_payload).decode('utf-8')
            elif isinstance(raw_payload, str):
                self.payload = raw_payload
                try:
                    self.payload_binary = base64.b64decode(raw_payload)
                except:
                    self.payload_binary = None
                    
        if raw_header:
            if isinstance(raw_header, (dict, list)):
                self.header_body = json.dumps(raw_header)
            elif isinstance(raw_header, str):
                self.header_body = raw_header
            else:
                self.header_body = str(raw_header)
                
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
            'response_code': self.response_code,
            'payload': self.payload,
            'header_body': self.header_body,  # 添加header_body到返回字典
            'risk_level': self.risk_level,
            'traffic_type': self.traffic_type,
            'threat_type': self.threat_type,
            'packet_type': self.packet_type,
        }