from extensions import db
from datetime import datetime

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(20), primary_key=False)
    sha256 = db.Column(db.String(64), unique=True, nullable=False)
    md5 = db.Column(db.String(32), unique=True, nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)

    yara_result = db.Column(db.Text, nullable=False)
    api_result = db.Column(db.Text, nullable=False)
    
    detection_time = db.Column(db.DateTime, nullable=False, default=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename':self.file_name,
            'sha256': self.sha256,
            'md5': self.md5,
            'fileType': self.file_type,
            'fileSize': self.file_size,
            'threatLevel': self.threat_level,
            'yara_result': self.yara_result,
            'api_result': self.api_result,
            'detectionTime': self.detection_time.isoformat()
        } 