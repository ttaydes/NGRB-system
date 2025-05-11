from datetime import datetime, timedelta
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
    tools = relationship("Tool", back_populates="category", lazy="dynamic")
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
    first_seen = db.Column(db.DateTime)                          # 首次发现时间
    last_seen = db.Column(db.DateTime)                           # 最后活动时间
    domain = db.Column(db.String(255))                           # 域名
    
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

# # 威胁情报查询工具类
# class ThreatIntelligenceService:
#     def __init__(self):
#         self.db = get_db()
        
#     def get_threat_stats(self, start_time):
#         """获取威胁统计信息"""
#         try:
#             # 获取当前统计
#             current_stats = self._get_stats_by_time(start_time)
            
#             # 获取前一周期统计（用于计算趋势）
#             previous_start = start_time - timedelta(hours=24)
#             previous_stats = self._get_stats_by_time(previous_start)
            
#             return {
#                 'current': current_stats,
#                 'previous': previous_stats
#             }
            
#         except Exception as e:
#             print(f"获取威胁统计失败: {e}")
#             return {
#                 'current': {},
#                 'previous': {}
#             }
    
#     def _get_stats_by_time(self, start_time):
#         """根据时间获取威胁统计"""
#         try:
#             cursor = self.db.cursor()
            
#             # 查询威胁统计
#             query = """
#                 SELECT 
#                     threat_type,
#                     COUNT(*) as count
#                 FROM threat_intelligence
#                 WHERE created_at >= %s
#                 GROUP BY threat_type
#             """
            
#             cursor.execute(query, (start_time,))
#             results = cursor.fetchall()
            
#             # 初始化统计结果
#             stats = {
#                 'top10': 0,
#                 'webshell': 0,
#                 'malware': 0,
#                 'cve': 0,
#                 'poc': 0,
#                 'ip': 0,
#                 'c2': 0,
#                 'sensitive': 0
#             }
            
#             # 填充统计结果
#             for row in results:
#                 threat_type = row[0]
#                 count = row[1]
#                 if threat_type in stats:
#                     stats[threat_type] = count
            
#             return stats
            
#         except Exception as e:
#             print(f"获取威胁统计失败: {e}")
#             return {}
            
#         finally:
#             cursor.close()

#     @staticmethod
#     def get_category_by_code(code):
#         """根据大类编码获取威胁大类"""
#         return ThreatCategory.query.filter_by(code=code).first()
    
#     @staticmethod
#     def get_category_by_name(name):
#         """根据大类名称获取威胁大类"""
#         return ThreatCategory.query.filter_by(name=name).first()
    
#     @staticmethod
#     def get_all_categories():
#         """获取所有威胁大类"""
#         return ThreatCategory.query.all()
    
#     @staticmethod
#     def match_traffic_with_intel(traffic_data):
#         """将流量数据与威胁情报进行匹配"""
#         matches = []
        
#         # 1. 检查是否匹配恶意IP
#         if 'source_ip' in traffic_data or 'destination_ip' in traffic_data:
#             src_ip = traffic_data.get('source_ip')
#             dst_ip = traffic_data.get('destination_ip')
            
#             # 查询恶意IP大类
#             ip_category = ThreatCategory.query.filter_by(code='malicious_ip').first()
#             if ip_category:
#                 # 检查源IP
#                 if src_ip:
#                     malicious_ips = MaliciousIP.query.filter_by(category_id=ip_category.id, ip_address=src_ip).all()
#                     for ip in malicious_ips:
#                         matches.append({
#                             'category': 'malicious_ip',
#                             'match_type': 'source_ip',
#                             'intel': ip.to_dict()
#                         })
                
#                 # 检查目标IP
#                 if dst_ip:
#                     malicious_ips = MaliciousIP.query.filter_by(category_id=ip_category.id, ip_address=dst_ip).all()
#                     for ip in malicious_ips:
#                         matches.append({
#                             'category': 'malicious_ip',
#                             'match_type': 'destination_ip',
#                             'intel': ip.to_dict()
#                         })
        
#         # 2. 检查是否匹配C2服务器
#         if 'destination_ip' in traffic_data or 'header_body' in traffic_data:
#             dst_ip = traffic_data.get('destination_ip')
#             header_body = traffic_data.get('header_body', '')
            
#             # 查询C2服务器大类
#             c2_category = ThreatCategory.query.filter_by(code='c2_server').first()
#             if c2_category:
#                 # 检查目标IP是否为C2服务器
#                 if dst_ip:
#                     c2_servers = C2Server.query.filter_by(category_id=c2_category.id, ip_address=dst_ip).all()
#                     for c2 in c2_servers:
#                         matches.append({
#                             'category': 'c2_server',
#                             'match_type': 'destination_ip',
#                             'intel': c2.to_dict()
#                         })
                
#                 # 检查域名是否为C2服务器
#                 if header_body:
#                     c2_servers = C2Server.query.filter(
#                         C2Server.category_id == c2_category.id,
#                         C2Server.domain.isnot(None)
#                     ).all()
                    
#                     for c2 in c2_servers:
#                         if c2.domain and c2.domain in header_body:
#                             matches.append({
#                                 'category': 'c2_server',
#                                 'match_type': 'domain_in_header',
#                                 'intel': c2.to_dict()
#                             })
        
#         # 3. 检查是否匹配其他威胁类型（基于特征匹配）
#         if 'payload' in traffic_data or 'header_body' in traffic_data:
#             payload = traffic_data.get('payload', '')
#             header_body = traffic_data.get('header_body', '')
            
#             # 获取所有威胁大类
#             categories = ThreatCategory.query.all()
            
#             for category in categories:
#                 # 根据不同大类进行特征匹配
#                 if category.code == 'top10_vulnerability':
#                     for vuln in Top10Vulnerability.query.filter_by(category_id=category.id, is_active=True).all():
#                         if vuln.pattern_content and (vuln.pattern_content in payload or vuln.pattern_content in header_body):
#                             matches.append({
#                                 'category': 'top10_vulnerability',
#                                 'match_type': 'pattern_match',
#                                 'intel': vuln.to_dict()
#                             })
                
#                 elif category.code == 'webshell_attack':
#                     for webshell in WebshellAttack.query.filter_by(category_id=category.id, is_active=True).all():
#                         if webshell.pattern_content and (webshell.pattern_content in payload or webshell.pattern_content in header_body):
#                             matches.append({
#                                 'category': 'webshell_attack',
#                                 'match_type': 'pattern_match',
#                                 'intel': webshell.to_dict()
#                             })
                
#                 # 其他大类的特征匹配逻辑类似...
        
#         return matches



class Tool(BaseThreatIntel):
    """恶意工具情报"""
    __tablename__ = 'tools'
    
    category_id = db.Column(db.Integer, ForeignKey('threat_categories.id'))
    category = relationship("ThreatCategory", back_populates="tools")

    tool_name = db.Column(db.String(255), nullable=False)
    tool_type = db.Column(db.String(50))

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
            'tool_name': self.tool_name,
            'tool_type': self.tool_type
        }   
    
    
