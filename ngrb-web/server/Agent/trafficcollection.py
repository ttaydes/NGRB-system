import logging
import threading
import time
import queue
from datetime import datetime,timedelta
import psycopg
import sys
import asyncio
import ssl
from urllib.parse import urlparse
import json
from traffic.http_packet import HttpThreatHunter
from traffic.icmp_packet import IcmpThreatHunter
from traffic.dns_packet import DnsThreatHunter
import pyshark
from threat_intelligence import MaliciousIP
from collections import defaultdict, Counter

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('traffic.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)



class TrafficCollector:
    def __init__(self):
        
        self.packet_queue = queue.Queue()
        self.running = False
        self.thread = None
        self.sniff_thread = None
        self.retry_count = 0
        self.max_retries = 3
        self.db_connection = None
        self.db_cursor = None
        self.http_sessions = {}  # 用于跟踪HTTP会话
        self.connect_db()
        self.current_packet = None
        # 添加SSL上下文用于HTTPS解析
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE


        self.scan_history = defaultdict(list)




        self.config = {
            'time_window': 60,  # 时间窗口（秒）
            'port_threshold': 3,  # 端口扫描阈值
            'syn_scan_threshold': 5,  # SYN扫描阈值
            'fin_scan_threshold': 3,  # FIN扫描阈值
            'xmas_scan_threshold': 3,  # XMAS扫描阈值
            'null_scan_threshold': 3,  # NULL扫描阈值
            'udp_scan_threshold': 5,  # UDP扫描阈值
        }
        # Nmap特征
        self.nmap_ttl_values = [37, 44, 64, 128, 255]  # Nmap常用TTL值
        self.nmap_window_sizes = [1024, 2048, 3072, 4096, 8192, 16384, 64240,65535]  # Nmap常用窗口大小


    def clean_old_records(self, source_ip):
        """清理过期的扫描记录"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.config['time_window'])
        
        # 过滤掉超过时间窗口的记录
        self.scan_history[source_ip] = [
            record for record in self.scan_history[source_ip]
            if record['timestamp'] > cutoff_time 
        ]
    
    def connect_db(self):
        """连接到数据库"""
        try:
            if self.db_connection and not self.db_connection.closed:
                self.db_cursor.close()
                self.db_connection.close()
            
            logger.info("正在连接数据库...")
            self.db_connection = psycopg.connect(
                dbname='ngrb',
                user='postgres',
                password='.',
                host='localhost',
                port='5432'
            )
            self.db_cursor = self.db_connection.cursor()
            
            # 检查表是否存在，如果不存在则创建
            self.db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP,
                    source_ip VARCHAR(45),
                    source_port INTEGER,
                    destination_ip VARCHAR(45),
                    destination_port INTEGER,
                    protocol VARCHAR(10),
                    packet_size INTEGER,
                    response_code INTEGER,
                    payload TEXT,
                    header_body TEXT,
                    risk_level TEXT,
                    threat_type TEXT,
                    traffic_type TEXT,
                    packet_type TEXT
                )
            """)
            self.db_connection.commit()
            logger.info("数据库连接成功，表结构已确认")
        except Exception as e:
            logger.error(f"数据库连接失败: {e}")
            raise

    def extract_http_info(self, packet,is_response):
        """提取HTTP信息"""
        try:
            header_body = []
            http_layer = packet.http
            # 检查是否存在HTTP层
            if not hasattr(packet, 'http'):
                logger.warning("未找到HTTP层")
                return ""
            
           
                
                # 特别处理一些常见的头部字段
            common_headers = {
                'host': 'Host',
                'user_agent': 'User-Agent',
                'accept': 'Accept',
                'accept_language': 'Accept-Language',
                'accept_encoding': 'Accept-Encoding',
                'connection': 'Connection',
                'cookie': 'Cookie',
                'referer': 'Referer',
                'server': 'Server',
                'date': 'Date',
                'content_type': 'Content-Type',
                'content_length': 'Content-Length',
                'last_modified': 'Last-Modified',
                'etag': 'ETag',
                'set_cookie': 'Set-Cookie',
                'expires': 'Expires',
                'pragma': 'Pragma',
                'cache_control': 'Cache-Control'
            }
            if not is_response:
                http_request_method = getattr(http_layer, 'request_method', '')
                host = getattr(http_layer, 'host', '未知主机')
                uri = getattr(http_layer, 'request_uri', '')
                header_body.append(f"{http_request_method} {host}")
                header_body.append(f"{uri}")

            elif is_response:
                http_response_code = getattr(http_layer, 'response_code', '')
                header_body.append(f"{http_response_code}")

            for field, header_name in common_headers.items():
                    try:
                        if hasattr(packet.http, field):
                            header_value = getattr(packet.http, field)
                            if header_value:
                                header_body.append(f"{header_name}: {header_value}")
                    except Exception as e:
                        logger.debug(f"提取常见头部字段 {header_name} 时出错: {e}")
                
                
                
            return "\n".join(header_body)
        except Exception as e:
            logger.error(f"HTTP信息提取错误: {e}")
            logger.debug(f"HTTP数据包字段: {dir(packet.http) if hasattr(packet, 'http') else 'No HTTP layer'}")
            return ""

    def extract_icmp_info(self, packet):
        """提取ICMP信息"""
        try:
            
            icmp_info = {}
            if not hasattr(packet, 'icmp'):
                return icmp_info
                
            
            icmp = packet.icmp
            icmp_info['type'] = getattr(icmp, 'type', None)

            icmp_info['code'] = getattr(icmp, 'code', None)
            icmp_info['checksum'] = getattr(icmp, 'checksum', None)
            icmp_info['size'] = packet.length 
            icmp_info['data'] = getattr(icmp, 'data', '')
            # 提取ICMP数据
            if hasattr(icmp, 'data'):
                # 确保数据是字符串类型，避免不可哈希类型错误
                icmp_info['data'] = str(icmp.data) if icmp.data else None
            
            return icmp_info
        except Exception as e:
            logger.error(f"ICMP信息提取错误: {e}")
            return {}

    def extract_https_info(self, packet):
        """提取HTTPS信息"""
        try:
            # 初始化返回信息
            https_info = ""
            
            # 检查是否存在TLS层
            if not hasattr(packet, 'tls'):
                return https_info
                
            logger.info("正在提取HTTPS信息...")
            
            # 提取TLS版本和握手类型等基本信息
            tls_info = []
            
            # 提取TLS版本
            if hasattr(packet.tls, 'record_version'):
                tls_info.append(f"TLS版本: {packet.tls.record_version}")
                
            # 提取握手类型
            if hasattr(packet.tls, 'handshake_type'):
                handshake_types = {
                    '1': 'Client Hello',
                    '2': 'Server Hello',
                    '11': 'Certificate',
                    '16': 'Client Key Exchange',
                    '14': 'Server Key Exchange'
                }
                handshake_type = packet.tls.handshake_type
                type_desc = handshake_types.get(handshake_type, handshake_type)
                tls_info.append(f"握手类型: {type_desc}")
            
            # 提取SNI信息(Server Name Indication)
            if hasattr(packet.tls, 'handshake_extensions_server_name'):
                tls_info.append(f"服务器名称: {packet.tls.handshake_extensions_server_name}")
            
            # 提取密码套件
            if hasattr(packet.tls, 'handshake_ciphersuite'):
                tls_info.append(f"密码套件: {packet.tls.handshake_ciphersuite}")
            
            # 提取证书信息
            if hasattr(packet.tls, 'handshake_certificate'):
                tls_info.append("证书信息: 包含证书数据")
            
            # 组合所有信息
            https_info = "\n".join(tls_info)
            
            return https_info
        except Exception as e:
            logger.error(f"HTTPS信息提取错误: {e}")
            logger.debug(f"HTTPS数据包字段: {dir(packet.tls) if hasattr(packet, 'tls') else 'No TLS layer'}")
            return ""

    def extract_dns_info(self, packet):
        """提取DNS信息"""
        try:
            dns_info = {}
            if not hasattr(packet, 'dns'):
                return dns_info

            dns = packet.dns
            dns_info['name'] = dns.qry_name
            dns_info['query'] = dns.qry_type
         
            return dns_info
        except Exception as e:
            logger.error(f"DNS信息提取错误: {e}")
            return {}



    def extract_tcp_info(self, packet):
        """提取TCP信息"""
        try:
            tcp_info = {}
            if not hasattr(packet, 'tcp'):
                return tcp_info
                
            tcp = packet.tcp
            tcp_info['src_port'] = tcp.srcport
            tcp_info['dst_port'] = tcp.dstport
            tcp_info['seq'] = getattr(tcp, 'seq', None)
            tcp_info['ack'] = getattr(tcp, 'ack', None)
            tcp_info['flags'] = getattr(tcp, 'flags', None)
            tcp_info['window_size'] = getattr(tcp, 'window_size', None)
            
            # 分析TCP标志位
            if hasattr(tcp, 'flags'):
                flags = tcp.flags
                logger.info(f"TCP标志位: {flags}")
                tcp_info['flags_analysis'] = {
                    'SYN': 'SYN' in flags,
                    'ACK': 'ACK' in flags,
                    'FIN': 'FIN' in flags,
                    'RST': 'RST' in flags,
                    'PSH': 'PSH' in flags,
                    'URG': 'URG' in flags
                }
                
            return tcp_info
        except Exception as e:
            logger.error(f"TCP信息提取错误: {e}")
            return {}

    def extract_udp_info(self, packet):
        """提取UDP信息"""
        try:
            udp_info = {}
            if not hasattr(packet, 'udp'):
                return udp_info
                
            udp = packet.udp
            udp_info['src_port'] = udp.srcport
            udp_info['dst_port'] = udp.dstport
            udp_info['length'] = getattr(udp, 'length', None)
            udp_info['checksum'] = getattr(udp, 'checksum', None)
            
            return udp_info
        except Exception as e:
            logger.error(f"UDP信息提取错误: {e}")
            return {}

    def analyze_packet_risk(self, protocol_type, packet_info):
        """分析数据包风险"""
        try:
            if protocol_type == "HTTP":
                http_threat_hunter = HttpThreatHunter(packet_info)
                hunter_threat = http_threat_hunter.detect_threat(packet_info["packet_type"])
                
                # 修改这里的处理逻辑
                if hunter_threat and isinstance(hunter_threat, list) and len(hunter_threat) > 0:
                    # 获取第一个威胁信息
                    first_threat = hunter_threat[0]
                    if isinstance(first_threat, dict):
                        return {
                            'category': first_threat.get('category', ''),
                            'severity': first_threat.get('severity', 'low'),
                            'confidence': first_threat.get('confidence', 0.0)
                        }
                return None

            
        except Exception as e:
            logger.error(f"风险分析错误: {e}")
            return None

    def track_http_session(self, packet_info):
        """跟踪HTTP会话"""
        try:
            if packet_info["protocol"] != "HTTP":
                return
            
            # 生成会话标识符
            session_key = f"{packet_info['source_ip']}:{packet_info['source_port']}-{packet_info['destination_ip']}:{packet_info['destination_port']}"
            
            # 更新会话信息
            if session_key not in self.http_sessions:
                self.http_sessions[session_key] = {
                    'start_time': datetime.now(),
                    'requests': [],
                    'responses': []
                }
            
            if packet_info["packet_type"] == "request_packet":
                self.http_sessions[session_key]['requests'].append({
                    'time': datetime.now(),
                    'info': packet_info
                })
            elif packet_info["packet_type"] == "response_packet":
                self.http_sessions[session_key]['responses'].append({
                    'time': datetime.now(),
                    'info': packet_info
                })
            
            # 清理过期会话
            self.cleanup_sessions()
            
        except Exception as e:
            logger.error(f"跟踪HTTP会话时出错: {e}")

    def cleanup_sessions(self):
        """清理过期会话"""
        try:
            current_time = datetime.now()
            expired_keys = []
            
            for key, session in self.http_sessions.items():
                # 如果会话超过5分钟没有活动，则清理
                if (current_time - session['start_time']).total_seconds() > 300:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.http_sessions[key]
            
        except Exception as e:
            logger.error(f"清理会话时出错: {e}")

    def save_to_db(self):
        """将数据包保存到数据库"""
        while self.running:
            try:
                packet_info = self.packet_queue.get(timeout=1)
                logger.info(f"准备保存数据包: {packet_info['protocol']} from {packet_info['source_ip']}:{packet_info['source_port']}")
                
                try:
                    if self.db_connection.closed:
                        logger.warning("数据库连接已关闭，尝试重新连接...")
                        self.connect_db()
                        
                    sql = """
                    INSERT INTO traffic (
                        timestamp, source_ip, source_port, destination_ip, destination_port,
                        protocol, packet_size, response_code, payload, header_body, risk_level, 
                        threat_type, traffic_type, packet_type
                    ) VALUES (%s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s,%s)
                    """
                    
                    params = (
                        packet_info["timestamp"],
                        packet_info["source_ip"],
                        packet_info["source_port"],
                        packet_info["destination_ip"],
                        packet_info["destination_port"],
                        packet_info["protocol"],
                        packet_info["packet_size"],
                        packet_info["response_code"],
                        packet_info["payload"],
                        packet_info["header_body"],
                        packet_info["risk_level"],
                        packet_info["threat_type"],
                        packet_info["traffic_type"],
                        packet_info["packet_type"]
                    )

                    self.db_cursor.execute(sql, params)
                    self.db_connection.commit()
                    logger.info(f"数据包保存成功: {packet_info['protocol']} from {packet_info['source_ip']}")
                    self.retry_count = 0
                    
                except psycopg.Error as e:
                    logger.error(f"数据库错误: {e}")
                    self.db_connection.rollback()
                    self.retry_count += 1
                    if self.retry_count < self.max_retries:
                        logger.warning(f"重试保存数据包 (尝试 {self.retry_count}/{self.max_retries})")
                        self.packet_queue.put(packet_info)
                        time.sleep(1)
                    else:
                        try:
                            logger.warning("达到最大重试次数，尝试重新连接数据库...")
                            self.connect_db()
                            self.retry_count = 0
                        except:
                            logger.error("数据库重连失败")
                            time.sleep(5)
                            
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"保存数据错误: {e}")
    def detect_nmap_scan(self, source_ip, current_scan, tcp_header):
        """
        检测各种Nmap扫描技术
        """
        result = {
            'category': 'normal',
            'severity': 'low',
            'confidence': 0,
        }
        
        # 获取当前源IP的所有扫描记录
        records = self.scan_history[source_ip]
        # 如果记录太少，可能不是扫描
        if len(records) < 3:
            return result
            
        # 1. 检测端口扫描 - 同一源IP短时间内扫描多个不同端口
        dest_ports = [r['dest_port'] for r in records]
        unique_ports = len(set(dest_ports))
        
        if unique_ports >= self.config['port_threshold']:
            result['category'] = 'port_scan'
            result['severity'] = 'medium'
            result['confidence'] = min(70 + (unique_ports - self.config['port_threshold']) * 2, 95)
        
        # 2. 检测SYN扫描 - 大量SYN包但没有完成连接
        syn_flags = [r for r in records if 'S' in r.get('flags', '') and 'A' not in r.get('flags', '')]
        if len(syn_flags) >= self.config['syn_scan_threshold']:
            result['category'] = 'nmap_scan'
            result['severity'] = 'high'
            result['confidence'] = min(80 + len(syn_flags) * 2, 98)
        
        num = 0
        for r in records:
            if r.get('flags') ==  '0x0002':
                num += 1
                if num >= 10:
                    
                    result['category'] = 'nmap_scan'
                    result['severity'] = 'high'
                    result['confidence'] = min(85 + num * 2, 98)




        # # 3. 检测FIN扫描 - 只有FIN标志的包
        # fin_flags = [r for r in records if  r.get('flags', '') ==  0x0002 and 'A' not in r.get('flags', '') and 'S' not in r.get('flags', '')]
        # if len(fin_flags) >= self.config['fin_scan_threshold']:
        #     result['category'] = 'nmap_scan'
        #     result['severity'] = 'high'
        #     result['confidence'] = min(85 + len(fin_flags) * 2, 98)
        
        
        
        # 6. 检测Nmap特征 - TTL值和窗口大小
        if tcp_header:
            ttl = tcp_header.get('ttl')
            window_size = tcp_header.get('window_size')
            
            if ttl in self.nmap_ttl_values and window_size in self.nmap_window_sizes:
                if result['category'] == 'normal':
                    result['category'] = 'suspicious'
                    result['severity'] = 'medium'
                    result['confidence'] = 60
                else:
                    result['confidence'] = min(result['confidence'] + 10, 99)
                
        
        # 7. 检测扫描间隔的规律性
        if len(records) >= 5:
            timestamps = sorted([r['timestamp'] for r in records])
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
            
            # 计算间隔的标准差，如果很小说明间隔很规律
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                
                # 方差小说明间隔规律
                if variance < 0.5 and avg_interval < 2.0:
                    if result['category'] == 'normal':
                        result['category'] = 'suspicious'
                        result['severity'] = 'medium'
                        result['confidence'] = 50
                    else:
                        result['confidence'] = min(result['confidence'] + 15, 99)
                    
        result['confidence'] = result['confidence'] / 100
        
        return result

    def start_sniffing(self):
        try:
            # 创建一个新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # 指定 tshark 的安装路径
            tshark_path = "E:\\TOOL\\catch-package\\Wireshark\\tshark.exe"
            
            logger.info("开始捕获网络流量...")
            capture = pyshark.LiveCapture(
                interface='VMware Network Adapter VMnet5',
                tshark_path=tshark_path                #抓取https
            )

            # 使用sniff_continuously持续捕获数据包
            for packet in capture.sniff_continuously():
                threats = []
                
                self.current_packet = packet
                if not self.running:
                    break
                
                try:
                    # 初始化数据包信息字典
                    packet_info = {
                        "timestamp": datetime.now(),
                        "source_ip": None,
                        "source_port": None,
                        "destination_ip": None,
                        "destination_port": None,
                        "protocol": None,
                        "packet_size": None,
                        "response_code": None,
                        "payload": None,
                        "header_body": None,
                        "risk_level": "low",
                        "threat_type": None,
                        "traffic_type": None,
                        "packet_type": "数据包"
                    }
                    
                    if 'IP' in packet:
                        packet_info["source_ip"] = packet.ip.src
                        packet_info["destination_ip"] = packet.ip.dst
                        packet_info["protocol"] = packet.transport_layer
                        packet_info["packet_size"] = packet.length
                    
                        

                        sql = """
                        select severity,confidence,ip_type from malicious_ips where ip_address = %s and is_active = '1'
                        """
                        for ip in [packet_info["source_ip"],packet_info["destination_ip"]]:
                            logger.info(f"查询恶意IP: {ip}")
                            self.db_cursor.execute(sql, (ip,))
                            malicious_ip_info= {}
                            malicious_ip = self.db_cursor.fetchone()

                            if malicious_ip:
                                malicious_ip_info['category'] = 'ip'
                                malicious_ip_info['ip_info'] = ip
                                malicious_ip_info['ip_type'] = malicious_ip[2]
                                malicious_ip_info['confidence'] = malicious_ip[1]
                                malicious_ip_info['severity'] = malicious_ip[0]
                                threats.append(malicious_ip_info)
                                # 这里将恶意ip数据结果整合
                           
                        packet_info["protocol"] = "TCP"
                        
                       
                        # 处理TCP流量
                        if 'TCP' in packet:
                            packet_info["source_port"] = packet.tcp.srcport
                            packet_info["destination_port"] = packet.tcp.dstport
                            tcp_info = self.extract_tcp_info(packet)
                            if tcp_info:
                                packet_info["header_body"] = json.dumps(tcp_info)
                                logger.info(f"TCP连接: {packet.ip.src}:{packet.tcp.srcport} -> {packet.ip.dst}:{packet.tcp.dstport}")

                           
                            # 处理HTTP流量
                            if 'HTTP' in packet:
                                packet_info["protocol"] = "HTTP"
                                is_response = False
                                try:                                    
                                                            
                                    http_layer = packet.http

                                    if hasattr(http_layer, 'request_method'):
                                    
                                        packet_info["packet_type"] = "request_packet"
                                        logger.info(f"HTTP请求数据: {http_layer.request_method} {http_layer.request_uri}")
                                        is_response = False
                                        if http_layer.request_method == 'POST':
                                            decoded_request = bytes.fromhex(http_layer.file_data.replace(":", "")).decode('utf-8')
                                            packet_info["payload"] = decoded_request
                                       
                                    if hasattr(http_layer, 'response_code'):
                                        packet_info["packet_type"] = "response_packet"
                                        is_response = True
                                        packet_info["response_code"] = http_layer.response_code
                                        decoded_response = bytes.fromhex(http_layer.file_data.replace(":", "")).decode('utf-8')
                                        packet_info["payload"]= decoded_response
                                    # 提取HTTP信息
                                    header_body = self.extract_http_info(packet, is_response)
                                    if header_body:
                                        logger.info("HTTP头部信息:")
                                        logger.info(header_body)
                                        packet_info["header_body"] = header_body
                                

                                except Exception as e:
                                    logger.error(f"HTTP数据包处理错误: {e}")
                                    logger.debug(f"HTTP数据包字段: {dir(packet.http)}")
                                    continue
                            elif 'TLS' in packet:
                                packet_info["protocol"] = "HTTPS"
                                packet_info["header_body"] = self.extract_https_info(packet)
                            
                            else:
                            #为tcp

                                result = {
                                            'category': 'normal',
                                            'severity': 'low',
                                            'confidence': 0,
                                        }

                                                        # 提取关键信息
                                source_ip = packet_info.get('source_ip')
                                dest_ip = packet_info.get('destination_ip')
                                dest_port = packet_info.get('destination_port')
                                
                                if not (source_ip and dest_ip and dest_port):
                                    return result
                                    
                                # 解析TCP头部信息
                                tcp_header = {}
                                header_body = packet_info.get('header_body')
                                if header_body:
                                    try:
                                        if isinstance(header_body, str):
                                            tcp_header = json.loads(header_body)
                                        elif isinstance(header_body, dict):
                                            tcp_header = header_body
                                    except:
                                        logger.error(f"解析TCP头部失败: {header_body}")
                                
                                # 记录当前扫描
                                scan_record = {
                                    'timestamp': datetime.now(),
                                    'dest_ip': dest_ip,
                                    'dest_port': dest_port,
                                    'flags': tcp_header.get('flags', ''),
                                    'window_size': tcp_header.get('window_size'),
                                    'ttl': tcp_header.get('ttl'),
                                    'options': tcp_header.get('options', [])
                                }
                                
                                # 添加到历史记录
                                self.scan_history[source_ip].append(scan_record)
                                # 清理旧记录
                                self.clean_old_records(source_ip)
                                # 分析扫描行为
                                tcphunter_result =  self.detect_nmap_scan(source_ip, scan_record, tcp_header)
                                if tcphunter_result['category'] != 'normal' and '"ack": "0"' in header_body:
                                    try:
                                        #将此时的源ip加入到黑名单
                                        # 检查是否已存在相同IP的黑名单记录  
                                        sql_check = """
                                        SELECT COUNT(*) 
                                        FROM malicious_ips 
                                        WHERE ip_address = %s AND is_active = TRUE
                                        """
                                        self.db_cursor.execute(sql_check, (source_ip,))
                                        existing_count = self.db_cursor.fetchone()[0]

                                        if existing_count == 0:
                                            # 插入新的黑名单记录
                                            sql_insert = """
                                            INSERT INTO malicious_ips (name,category_id,ip_address, ip_type, confidence, severity, first_seen, is_active)
                                            VALUES (%s,%s,%s, %s, %s, %s, %s, TRUE)
                                            """ 
                                            # 使用参数化查询正确处理日期
                                            self.db_cursor.execute(sql_insert, (
                                                source_ip,
                                                8,
                                                source_ip,
                                                'attacker',
                                                tcphunter_result['confidence'],
                                                tcphunter_result['severity'],
                                                datetime.now()
                                            ))
                                            # 提交事务
                                            self.db_connection.commit()
                                            logger.info(f"已将IP {source_ip} 添加到黑名单")
                                    except Exception as e:
                                        # 回滚事务
                                        self.db_connection.rollback()
                                        logger.error(f"添加黑名单记录时出错: {e}")

                                threats.append(tcphunter_result)    
                                
                                                # 处理UDP流量
                        elif 'UDP' in packet:
                            packet_info["protocol"] = "UDP"
                            packet_info["source_port"] = packet.udp.srcport
                            packet_info["destination_port"] = packet.udp.dstport
                            udp_info = self.extract_udp_info(packet)
                            if udp_info:
                                packet_info["header_body"] = json.dumps(udp_info)
                                logger.info(f"UDP包: {packet.ip.src}:{packet.udp.srcport} -> {packet.ip.dst}:{packet.udp.dstport}")
                            if 'DNS' in packet:
                                packet_info["protocol"] = "DNS"
                                dns_info = self.extract_dns_info(packet)
                                if dns_info:
                                    packet_info["header_body"] = json.dumps(dns_info)
                                    dns_threat_hunter = DnsThreatHunter(packet_info['header_body'],self.db_cursor,self.db_connection)
                                    hunter_threat = dns_threat_hunter.detect_threat()
                                    if hunter_threat:
                                        threats.append(hunter_threat)
                                        logger.info(f"DNS威胁: {hunter_threat}")



                        # 处理ICMP流量
                        elif 'ICMP' in packet:
                            packet_info["protocol"] = "ICMP"
                            logger.info(f"捕获到ICMP数据包")
                            icmp_info = self.extract_icmp_info(packet)
                            if icmp_info:
                                logger.info(f"捕获到ICMP数据包{icmp_info}")
                                packet_info["header_body"] = icmp_info
                     
                                icmp_threat_hunter = IcmpThreatHunter(packet_info['header_body'])
                                hunter_threat = icmp_threat_hunter.detect_threat()
                                if hunter_threat:
                                    threats.append(hunter_threat)
                                    logger.info(f"ICMP威胁: {hunter_threat}")



                        # 在保存数据包之前添加会话跟踪
                        self.track_http_session(packet_info)
                        
                        hunter_result = self.analyze_packet_risk(packet_info["protocol"], packet_info)
                        threats.append(hunter_result)
                        valid_threats = [item for item in threats if item is not None]

                        packet_info["threat_type"] = str(valid_threats)

                        if threats and valid_threats:
                            severity_order = ['low', 'medium', 'high']
                        # 找出 confidence 最大的项
                            max_conf_item = max(valid_threats, key=lambda x: x.get('confidence', 0))
                            max_conf_category = max_conf_item['category']
                            max_conf_confidence = max_conf_item['confidence']
                            max_severity = max(
                                    (item['severity'] for item in valid_threats if 'severity' in item),
                                    key=lambda sev: severity_order.index(sev)
                                )

                            packet_info["traffic_type"] = max_conf_category
                            packet_info["risk_level"] = max_severity
                            packet_info["confidence"] =max_conf_confidence 

                        logger.info(f"威胁分析结果: {packet_info['risk_level']}")
                        # 将数据包信息放入队列
                        self.packet_queue.put(packet_info)
                        logger.info(f"数据包已加入队列: {packet_info['protocol']}")
                        
                except Exception as e:
                    logger.error(f"数据包处理错误: {e}")
                    logger.debug(f"数据包详细信息: {packet}")
                    
        except Exception as e:
            logger.error(f"抓包错误: {e}")
            if self.running:
                time.sleep(1)
                self.start_sniffing()

    def start(self):
        """启动流量收集"""
        if self.running:
            return

        self.running = True
        
        # 启动保存数据线程
        self.thread = threading.Thread(target=self.save_to_db)
        self.thread.daemon = True
        self.thread.start()
        
        # 启动抓包线程
        self.sniff_thread = threading.Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        logger.info("流量收集器启动成功")

    def stop(self):
        """停止流量收集"""
        self.running = False
        if self.thread:
            self.thread.join()
        if self.sniff_thread:
            self.sniff_thread.join()
        if self.db_cursor:
            self.db_cursor.close()
        if self.db_connection:
            self.db_connection.close()
        logger.info("流量收集器已停止")
if __name__ == "__main__":
    collector = TrafficCollector()
    try:
        collector.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        collector.stop()
    except Exception as e:
        logger.error(f"致命错误: {e}")
        collector.stop()
