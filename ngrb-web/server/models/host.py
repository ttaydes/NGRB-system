from datetime import datetime
from extensions import db

class Host(db.Model):
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    os_type = db.Column(db.String(50))  # Linux/Windows
    os_version = db.Column(db.String(100))
    status = db.Column(db.String(20), default='offline')  # online/offline
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProcessInfo(db.Model):
    __tablename__ = 'process_info'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'))
    process_name = db.Column(db.String(255))
    pid = db.Column(db.Integer)
    connections = db.Column(db.JSON)
    user = db.Column(db.String(100))
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    start_time = db.Column(db.DateTime)
    command_line = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ServiceInfo(db.Model):
    __tablename__ = 'service_info'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'))
    service_name = db.Column(db.String(255))
    status = db.Column(db.String(50))  # running/stopped
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    start_type = db.Column(db.String(50))
    display_name = db.Column(db.String(255))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecurityScan(db.Model):
    __tablename__ = 'security_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'))
    scan_type = db.Column(db.String(50))  # service_scan/log_analysis
    status = db.Column(db.String(20))  # running/completed/failed
    findings = db.Column(db.JSON)
    risk_level = db.Column(db.String(20))  # high/medium/low
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
