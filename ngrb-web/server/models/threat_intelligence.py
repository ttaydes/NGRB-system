from datetime import datetime
from extensions import db

class BaseIntelligence(db.Model):
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(255))
    description = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.now)
    last_seen = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class IPIntelligence(BaseIntelligence):
    __tablename__ = 'ip_intelligence'
    
    ip = db.Column(db.String(45), unique=True, nullable=False)  # Support for IPv6
    country = db.Column(db.String(100))
    asn = db.Column(db.String(50))
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.ip,
            'type': self.type,
            'source': self.source,
            'description': self.description,
            'country': self.country,
            'asn': self.asn,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }

class FileIntelligence(BaseIntelligence):
    __tablename__ = 'file_intelligence'
    
    hash = db.Column(db.String(64), unique=True, nullable=False)  # SHA256
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    
    def to_dict(self):
        return {
            'id': self.id,
            'hash': self.hash,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'type': self.type,
            'source': self.source,
            'description': self.description,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }

class C2Intelligence(BaseIntelligence):
    __tablename__ = 'c2_intelligence'
    
    domain = db.Column(db.String(255), unique=True, nullable=False)
    ip = db.Column(db.String(45))  # Support for IPv6
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    
    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'type': self.type,
            'source': self.source,
            'description': self.description,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }

class TrafficIntelligence(BaseIntelligence):
    __tablename__ = 'traffic_intelligence'
    
    name = db.Column(db.String(255), unique=True, nullable=False)
    pattern = db.Column(db.Text)  # 正则表达式或特征模式
    protocol = db.Column(db.String(20))
    port = db.Column(db.Integer)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'pattern': self.pattern,
            'protocol': self.protocol,
            'port': self.port,
            'type': self.type,
            'source': self.source,
            'description': self.description,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        } 