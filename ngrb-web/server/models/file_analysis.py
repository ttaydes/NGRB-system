from datetime import datetime
from extensions import db

class FileAnalysis(db.Model):
    __tablename__ = 'file_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), unique=True, nullable=False)
    file_type = db.Column(db.String(255))
    threat_level = db.Column(db.String(20))
    threat_type = db.Column(db.String(50))
    confidence = db.Column(db.Integer)
    upload_time = db.Column(db.DateTime, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'sha256': self.sha256,
            'file_type': self.file_type,
            'threat_level': self.threat_level,
            'threat_type': self.threat_type,
            'confidence': self.confidence,
            'upload_time': self.upload_time.isoformat()
        } 