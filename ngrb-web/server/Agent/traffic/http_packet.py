import re
import logging
import json
import psycopg
import urllib.parse
logger = logging.getLogger(__name__)

class HttpThreatHunter:
    def __init__(self, packets_info):
        self.packets_info = packets_info
        self.db_connection = None
        self.db_cursor = None
        self.connect_db()
        self.threat_patterns = self._load_threat_patterns()
        
    def connect_db(self):
        """连接到数据库"""
        try:
            self.db_connection = psycopg.connect(
                dbname='ngrb',
                user='postgres',
                password='.',
                host='localhost',
                port='5432'
            )
            self.db_cursor = self.db_connection.cursor()
        except Exception as e:
            logger.error(f"数据库连接失败: {e}")
            raise
    def _url_decode(self, content):
            """URL解码函数"""
            if not content:
                return content
            try:
                # 尝试多次解码，直到无法继续解码
                decoded = content
                while True:
                    try:
                        new_decoded = urllib.parse.unquote(decoded)
                        if new_decoded == decoded:
                            break
                        decoded = new_decoded
                    except:
                        break
                return decoded
            except Exception as e:
                logger.error(f"URL解码失败: {e}")
                return content

    def _load_threat_patterns(self):
        """加载所有威胁特征模式"""
        patterns = {
            'top10': {'request_header':[],'response_header':[],'request_payload':[],'response_payload':[],'url':[],'cookie':[],'all':[]},
            'webshell': {'request_header':[],'response_header':[],'request_payload':[],'response_payload':[],'url':[],'cookie':[],'all' :[]},
            'cve': {'request_header':[],'response_header':[],'request_payload':[],'response_payload':[],'url':[],'cookie':[],'all' :[]},
            'poc': {'request_header':[],'response_header':[],'request_payload':[],'response_payload':[],'url':[],'cookie':[],'all' :[]},
            'sensitive': {'request_header':[],'response_header':[],'request_payload':[],'response_payload':[],'url':[],'cookie':[],'all':[]}
            
        }
        
        try:
            # 加载 Top10 漏洞特征
            self.db_cursor.execute("""
                SELECT pattern_content, confidence, severity, match_location
                FROM top10_vulnerabilities 
                WHERE is_active = true
            """)
            
            for row in self.db_cursor.fetchall():
                if row[0]:  # pattern_content
                    patterns['top10'][row[3]].append({
                        'pattern_content': row[0],
                        'confidence': row[1],
                        'severity': row[2]
                    })
            
            # 加载 Webshell 特征
            self.db_cursor.execute("""
                SELECT pattern_content, confidence, severity, match_location
                FROM webshell_attacks 
                WHERE is_active = true
            """)
            for row in self.db_cursor.fetchall():
                if row[0]:
                    patterns['webshell'][row[3]].append({
                        'pattern_content': row[0],
                        'confidence': row[1],
                        'severity': row[2]
                    })
            
            # 加载 CVE 特征
            self.db_cursor.execute("""
                SELECT pattern_content, confidence, severity, match_location
                FROM cves 
                WHERE is_active = true
            """)
            for row in self.db_cursor.fetchall():
                if row[0]:
                    patterns['cve'][row[3]].append({
                        'pattern_content': row[0],
                        'confidence': row[1],
                        'severity': row[2]
                    })
            
            # 加载 POC 特征
            self.db_cursor.execute("""
                SELECT pattern_content, confidence, severity, match_location
                FROM pocs 
                WHERE is_active = true
            """)
            for row in self.db_cursor.fetchall():
                if row[0]:
                    patterns['poc'][row[3]].append({
                        'pattern_content': row[0],
                        'confidence': row[1],
                        'severity': row[2]
                    })
            
            # 加载敏感信息特征
            self.db_cursor.execute("""
                SELECT pattern_content, confidence, severity, match_location
                FROM sensitive_infos 
                WHERE is_active = true
            """)
            for row in self.db_cursor.fetchall():
                if row[0]:
                    patterns['sensitive'][row[3]].append({
                        'pattern_content': row[0],
                        'confidence': row[1],
                        'severity': row[2]
                    })
                    
            # 加载所有威胁特征
        except Exception as e:
            logger.error(f"加载威胁特征模式失败: {e}")
        finally:
            if self.db_cursor:
                self.db_cursor.close()
            if self.db_connection:
                self.db_connection.close()
            
        return patterns
    
    def __del__(self):
        """析构函数，确保关闭数据库连接"""
        if hasattr(self, 'db_cursor') and self.db_cursor:
            self.db_cursor.close()
        if hasattr(self, 'db_connection') and self.db_connection:
            self.db_connection.close()

    def detect_threat(self, packet_type):
        """检测HTTP会话中的威胁"""
        threats = []
        
        try:
            # 1. 检查请求包
            if packet_type == "request_packet":
                request_threats = self._analyze_packet(
                    self.packets_info,
                    is_request=True
                )
                if request_threats:
                    threats.extend(request_threats)
            
            # 2. 检查响应包
            elif packet_type == "response_packet":
                response_threats = self._analyze_packet(
                    self.packets_info,
                    is_request=False
                )
                if response_threats:
                    threats.extend(response_threats)
            
            # 整合威胁信息
            return self._consolidate_threats(threats)
            
        except Exception as e:
            logger.error(f"威胁检测失败: {e}")
            return []

    def _analyze_packet(self, packet_info, is_request=True):
        """分析单个数据包"""
        threats = []
        
        try:
          
            header_body = packet_info["header_body"]
            payload = packet_info["payload"]
              # 对header和payload进行URL解码
            decoded_header = self._url_decode(header_body)
            logger.info(f"解码后的头部信息: {decoded_header}")
            decoded_payload = self._url_decode(payload)
            logger.info(f"解码后的负载信息: {decoded_payload}")
            # 1. 检查头部信息
            header_threats = self._check_headers(decoded_header, is_request)
            threats.extend(header_threats)
            
            # 2. 检查负载内容
            payload_threats = self._check_payload(decoded_payload, is_request)
            threats.extend(payload_threats)
            
            # # 3. 检查URL参数
            # if is_request and hasattr(http_layer, 'request_uri'):
            #     url_threats = self._check_url(http_layer.request_uri)
            #     threats.extend(url_threats)
            
            return threats
            
        except Exception as e:
            logger.error(f"数据包分析失败: {e}")
            return []

    def _check_headers(self, headers, is_request):
        """检查HTTP头部信息"""
        threats = []
        
        try:
            if is_request:
                # 检查所有威胁模式
                for category, patterns in self.threat_patterns.items():
                    #匹配request_header 和 all
                    for threat_info in patterns['request_header']:
                        if self._match_pattern(threat_info['pattern_content'], headers):
                      
                            threats.append({
                                'category': category,
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                                })
                            
                    for threat_info in patterns['all']:
                        if self._match_pattern(threat_info['pattern_content'], headers):
                            threats.append({
                                'category': category,
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                                })
            elif is_request == False:
                for category, patterns in self.threat_patterns.items():
                    for threat_info in patterns['response_header']:
                        if self._match_pattern(threat_info['pattern_content'], headers):
                            threats.append({
                                'category': category,
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                                })
                    for threat_info in patterns['all']:
                        if self._match_pattern(threat_info['pattern_content'], headers):
                            threats.append({
                                'category': category,
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                                })
            return threats
            
        except Exception as e:
            logger.error(f"头部检查失败: {e}")
            return []

    def _check_payload(self, payload, is_request):
        """检查负载内容"""
        threats = []
        
        try:
            # 检查所有威胁模式
            if is_request:
                for category, patterns in self.threat_patterns.items():
                    for threat_info in patterns['request_payload']:
                        if self._match_pattern(threat_info['pattern_content'], payload):
                            threats.append({
                                'category': category,
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                            })
            elif is_request == False:
                for category, patterns in self.threat_patterns.items():
                    for threat_info in patterns['response_payload']:
                        if self._match_pattern(threat_info['pattern_content'], payload):
                            threats.append({
                                'category': category,
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                            })

            return threats
            
        except Exception as e:
            logger.error(f"负载检查失败: {e}")
            return []

    def _check_url(self, url):
        """检查URL参数"""
        threats = []
        
        try:
     
            # 检查所有威胁模式
            for category, patterns in self.threat_patterns.items():
                for threat_info in patterns['url']:
                    if self._match_pattern(threat_info['pattern_content'], url):
                            threats.append({
                                'category': category,
                                'threat_info': threat_info,
                                'match_type': 'url',
                                'confidence': threat_info['confidence'],
                                'severity': threat_info['severity']
                            })
            
            return threats
            
        except Exception as e:
            logger.error(f"URL检查失败: {e}")
            return []

    def _match_pattern(self, pattern, content):
        """匹配威胁特征"""
        try:
            if not pattern or not content:
                return False
            return bool(re.search(pattern, content))
            
                
        except Exception as e:
            logger.error(f"特征匹配失败: {e}")
            return False
#   def _analyze_combined(self, request_packet, response_packet):
#         """综合分析请求和响应"""
#         threats = []
        
#         try:
#             # 1. 检查响应状态码
#             if hasattr(response_packet.http, 'response_code'):
#                 status_code = response_packet.http.response_code
#                 if status_code in ['401', '403']:
#                     threats.append({
#                         'category': 'sensitive',
#                         'threat_info': {
#                             'name': '未授权访问尝试',
#                             'severity': 'high',
#                             'confidence': 0.8
#                         },
#                         'match_type': 'status_code',
#                         'confidence': 0.8,
#                         'severity': 'high'
#                     })
            
#             # 2. 检查请求方法和响应内容的组合
#             if (hasattr(request_packet.http, 'request_method') and 
#                 hasattr(response_packet.http, 'file_data')):
#                 method = request_packet.http.request_method
#                 response_data = response_packet.http.file_data
                
#                 # 检查敏感信息泄露
#                 if method == 'GET' and self._check_sensitive_info(response_data):
#                     threats.append({
#                         'category': 'sensitive',
#                         'threat_info': {
#                             'name': '敏感信息泄露',
#                             'severity': 'high',
#                             'confidence': 0.9
#                         },
#                         'match_type': 'combined',
#                         'confidence': 0.9,
#                         'severity': 'high'
#                     })
            
#             return threats
            
#         except Exception as e:
#             logger.error(f"综合分析失败: {e}")
#             return []

  
    def _check_sensitive_info(self, content):
        """检查敏感信息泄露"""
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'secret["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # 邮箱
            r'\d{17}[\dXx]',  # 身份证
            r'\d{11}'  # 手机号
        ]
        
        try:
            for pattern in sensitive_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            return False
            
        except Exception as e:
            logger.error(f"敏感信息检查失败: {e}")
            return False

    def _consolidate_threats(self, threats):
        """整合威胁信息"""
        try:
            if not threats:
                return []
            
            # 按严重程度排序
            threats.sort(key=lambda x: self._get_severity_score(x.get('severity', 'low')), reverse=True)
            
            # 去重
            unique_threats = []
            seen = set()
            
            for threat in threats:
                if not isinstance(threat, dict):
                    continue
                
                category = threat.get('category', '')
                threat_info = threat.get('threat_info', {})
                threat_id = threat_info.get('id', '') if isinstance(threat_info, dict) else ''
                
                key = f"{category}:{threat_id}"
                if key not in seen:
                    seen.add(key)
                    unique_threats.append(threat)
            
            return unique_threats
            
        except Exception as e:
            logger.error(f"威胁整合失败: {e}")
            return threats

    def _get_severity_score(self, severity):
        """获取严重程度分数"""
        severity_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return severity_scores.get(str(severity).lower(), 0)


        