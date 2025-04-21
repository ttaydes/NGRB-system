from extensions import db
from datetime import datetime

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(20), primary_key=False)
    sha256 = db.Column(db.String(64), unique=True, nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)
    detection_time = db.Column(db.DateTime, nullable=False, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename':self.filename,
            'sha256': self.sha256,
            'fileType': self.file_type,
            'fileSize': self.file_size,
            'threatLevel': self.threat_level,
            'detectionTime': self.detection_time.isoformat()
        } 