from datetime import datetime
from extensions import db
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship

class ThreatCategory(db.Model):
    """威胁大类主表"""
    __tablename__ = 'threat_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)  # 大类名称，如 top10漏洞、webshell攻击等
    code = db.Column(db.String(20), nullable=False, unique=True)  # 大类编码，用于快速查询
    description = db.Column(db.Text)                              # 大类描述
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # 关联关系
    top10_vulnerabilities = relationship("Top10Vulnerability", back_populates="category", lazy="dynamic")
    webshell_attacks = relationship("WebshellAttack", back_populates="category", lazy="dynamic")
    malwares = relationship("Malware", back_populates="category", lazy="dynamic")
    cves = relationship("CVE", back_populates="category", lazy="dynamic")
    pocs = relationship("POC", back_populates="category", lazy="dynamic")
    malicious_ips = relationship("MaliciousIP", back_populates="category", lazy="dynamic")
    c2_servers = relationship("C2Server", back_populates="category", lazy="dynamic")
    sensitive_infos = relationship("SensitiveInfo", back_populates="category", lazy="dynamic")
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

# 基础威胁情报模型（作为所有分表的基类）
class BaseThreatIntel(db.Model):
    """威胁情报基础模型"""
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    source = db.Column(db.String(100))                           # 情报来源
    confidence = db.Column(db.Float)                             # 可信度评分
    severity = db.Column(db.String(20))                          # 严重程度
    is_active = db.Column(db.Boolean, default=True)              # 是否激活
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # 特征匹配相关字段
    pattern_content = db.Column(db.Text)                         # 特征内容
    match_location = db.Column(db.String(50))                    # 匹配位置
    is_regex = db.Column(db.Boolean, default=False)              # 是否为正则表达式
    tags = db.Column(db.String(255))                             # 标签
    reference = db.Column(db.Text)                               # 参考信息

# 各大类威胁情报分表模型
class Top10Vulnerability(BaseThreatIntel):
    """Top10漏洞情报"""
    __tablename__ = 'top10_vulnerabilities'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="top10_vulnerabilities")
    
    vulnerability_type = db.Column(db.String(50))                # 漏洞类型
    cwe_id = db.Column(db.String(20))                            # CWE编号
    affected_systems = db.Column(db.Text)                        # 受影响系统
    mitigation = db.Column(db.Text)                              # 缓解措施
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'vulnerability_type': self.vulnerability_type,
            'cwe_id': self.cwe_id,
            'affected_systems': self.affected_systems,
            'mitigation': self.mitigation
        }

class WebshellAttack(BaseThreatIntel):
    """Webshell攻击情报"""
    __tablename__ = 'webshell_attacks'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="webshell_attacks")
    
    shell_type = db.Column(db.String(50))                        # Webshell类型
    language = db.Column(db.String(50))                          # 脚本语言
    file_extension = db.Column(db.String(20))                    # 文件扩展名
    detection_method = db.Column(db.String(50))                  # 检测方法
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'shell_type': self.shell_type,
            'language': self.language,
            'file_extension': self.file_extension,
            'detection_method': self.detection_method
        }

class Malware(BaseThreatIntel):
    """木马情报"""
    __tablename__ = 'malwares'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="malwares")
    
    malware_type = db.Column(db.String(50))                      # 木马类型
    file_hash = db.Column(db.String(64))                         # 文件哈希
    file_type = db.Column(db.String(50))                         # 文件类型
    behavior = db.Column(db.Text)                                # 行为特征
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'malware_type': self.malware_type,
            'file_hash': self.file_hash,
            'file_type': self.file_type,
            'behavior': self.behavior
        }

class CVE(BaseThreatIntel):
    """CVE漏洞情报"""
    __tablename__ = 'cves'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="cves")
    
    cve_id = db.Column(db.String(20), nullable=False)            # CVE编号
    cvss_score = db.Column(db.Float)                             # CVSS评分
    affected_products = db.Column(db.Text)                       # 受影响产品
    patch_info = db.Column(db.Text)                              # 补丁信息
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'affected_products': self.affected_products,
            'patch_info': self.patch_info
        }

class POC(BaseThreatIntel):
    """POC情报"""
    __tablename__ = 'pocs'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="pocs")
    
    poc_content = db.Column(db.Text, nullable=False)             # POC内容
    target_type = db.Column(db.String(50))                       # 目标类型
    exploit_method = db.Column(db.String(100))                   # 利用方法
    related_cve = db.Column(db.String(20))                       # 相关CVE
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'poc_content': self.poc_content,
            'target_type': self.target_type,
            'exploit_method': self.exploit_method,
            'related_cve': self.related_cve
        }

class MaliciousIP(BaseThreatIntel):
    """恶意IP情报"""
    __tablename__ = 'malicious_ips'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="malicious_ips")
    
    ip_address = db.Column(db.String(50), nullable=False)        # IP地址
    ip_type = db.Column(db.String(50))                           # IP类型
    country = db.Column(db.String(50))                           # 国家/地区
    asn = db.Column(db.String(50))                               # ASN信息
    first_seen = db.Column(db.DateTime)                          # 首次发现时间
    last_seen = db.Column(db.DateTime)                           # 最后活动时间
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'ip_address': self.ip_address,
            'ip_type': self.ip_type,
            'country': self.country,
            'asn': self.asn,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }

class C2Server(BaseThreatIntel):
    """C2服务信息情报"""
    __tablename__ = 'c2_servers'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="c2_servers")
    
    ip_address = db.Column(db.String(50))                        # IP地址
    domain = db.Column(db.String(255))                           # 域名
    c2_type = db.Column(db.String(50))                           # C2类型
    malware_family = db.Column(db.String(100))                   # 恶意软件家族
    protocol = db.Column(db.String(50))                          # 通信协议
    port = db.Column(db.Integer)                                 # 端口
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'ip_address': self.ip_address,
            'domain': self.domain,
            'c2_type': self.c2_type,
            'malware_family': self.malware_family,
            'protocol': self.protocol,
            'port': self.port
        }

class SensitiveInfo(BaseThreatIntel):
    """敏感信息泄露/操作情报"""
    __tablename__ = 'sensitive_infos'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="sensitive_infos")
    
    info_type = db.Column(db.String(50))                         # 敏感信息类型
    data_pattern = db.Column(db.Text)                            # 数据模式
    operation_type = db.Column(db.String(50))                    # 操作类型
    affected_system = db.Column(db.String(100))                  # 受影响系统
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'pattern_content': self.pattern_content,
            'match_location': self.match_location,
            'is_regex': self.is_regex,
            'tags': self.tags,
            'reference': self.reference,
            'info_type': self.info_type,
            'data_pattern': self.data_pattern,
            'operation_type': self.operation_type,
            'affected_system': self.affected_system
        }
