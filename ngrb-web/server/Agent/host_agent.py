import os
import sys
import json
import platform
import psutil
import requests
import socket
import logging
from datetime import datetime
import nmap
import paramiko
import win32serviceutil
import win32service
import win32event
import servicemanager
import time
from pathlib import Path
import win32api
import win32con
import win32security
import win32process
import win32com.client
import pythoncom
import wmi

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('host_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HostAgent:
    def __init__(self, server_url):
        self.server_url = server_url
        self.host_info = self._get_host_info()
        self.nm = nmap.PortScanner()

    def _get_host_info(self):
        """获取主机基本信息"""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            os_info = platform.system() + " " + platform.release()
            
            return {
                'hostname': hostname,
                'ip_address': ip_address,
                'os_type': platform.system(),
                'os_version': platform.release(),
                'status': 'online'
            }
        except Exception as e:
            logger.error(f"获取主机信息失败: {str(e)}")
            return None

    def get_process_info(self):
        """获取进程信息"""
        processes = []
        try:
            # 获取所有进程的CPU使用率
            cpu_percent_dict = {}
            for proc in psutil.process_iter(['pid']):
                try:
                    cpu_percent_dict[proc.info['pid']] = proc.cpu_percent(interval=0.1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # 获取网络连接信息
            connections = {}
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid:
                    if conn.pid not in connections:
                        connections[conn.pid] = []
                    connections[conn.pid].append({
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'type': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                    })

            # 获取进程详细信息
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'create_time', 'cmdline']):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    
                    # 获取进程的CPU使用率
                    cpu_usage = cpu_percent_dict.get(pid, 0)
                    
                    # 获取进程的网络连接
                    process_connections = connections.get(pid, [])
                    
                    processes.append({
                        'process_name': pinfo['name'],
                        'pid': pid,
                        'connections': process_connections,
                        'user': pinfo['username'],
                        'cpu_usage': round(cpu_usage, 2),  # 保留两位小数
                        'memory_usage': round(pinfo['memory_percent'], 2),  # 保留两位小数
                        'start_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo['create_time'] else None,
                        'command_line': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else None,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            logger.error(f"获取进程信息失败: {str(e)}")
        return processes

    def get_service_info(self):
        """获取服务信息"""
        services = []
        if platform.system() == 'Windows':
            services = self._get_windows_services()
        else:
            services = self._get_linux_services()
        return services

    def _get_windows_services(self):
        """获取Windows服务信息"""
        services = []
        try:
            # 使用WMI获取服务信息
            pythoncom.CoInitialize()
            wmi_obj = wmi.WMI()
            for service in wmi_obj.Win32_Service():
                services.append({
                    'service_name': service.Name,
                    'status': service.State,
                    'start_type': service.StartMode,
                    'display_name': service.DisplayName,
                    'description': service.Description
                })
        except Exception as e:
            logger.error(f"获取Windows服务信息失败: {str(e)}")
        finally:
            pythoncom.CoUninitialize()
        return services

    def _get_linux_services(self):
        """获取Linux服务信息"""
        services = []
        try:
            # 使用systemctl获取服务状态
            import subprocess
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        services.append({
                            'service_name': parts[0],
                            'status': 'running',
                            'description': ' '.join(parts[3:])
                        })
        except Exception as e:
            logger.error(f"获取Linux服务信息失败: {str(e)}")
        return services

        """扫描开放端口"""
        try:
            self.nm.scan(self.host_info['ip_address'], arguments='-sS -sV -F')
            services = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        services.append({
                            'port': port,
                            'protocol': proto,
                            'service_name': service.get('name', 'unknown'),
                            'version': service.get('version', 'unknown'),
                            'status': 'open'
                        })
            return services
        except Exception as e:
            logger.error(f"端口扫描失败: {str(e)}")
            return []

    def analyze_logs(self):
        """分析系统日志"""
        findings = []
        if platform.system() == 'Windows':
            findings.extend(self._analyze_windows_logs())
        else:
            findings.extend(self._analyze_linux_logs())
        return findings

    def _analyze_windows_logs(self):
        """分析Windows日志"""
        findings = []
        
        try:
            logger.info("分析Windows日志")
            import win32evtlog
            import win32evtlogutil
            import win32con
            
            # 定义需要分析的日志类型
            log_types = ['Security', 'System', 'Application']
            
            # 定义重要的安全事件ID
            security_event_ids = {
                # 登录事件
                4624: '成功登录',
                4625: '登录失败',
                4634: '注销',
                4648: '使用显式凭据尝试登录',
                4672: '分配特殊权限',
                # 账户管理
                4720: '创建用户账户',
                4722: '启用用户账户',
                4723: '尝试更改账户密码',
                4724: '尝试重置账户密码',
                4725: '禁用用户账户',
                4726: '删除用户账户',
                4738: '用户账户已更改',
                4740: '用户账户已锁定',
                # 组策略
                4739: '域策略已更改',
                # 系统事件
                1102: '审核日志已清除',
                # 特权使用
                4673: '特权服务被调用',
                4674: '尝试对特权对象执行操作',
                # 进程执行
                4688: '新进程已创建',
                4689: '进程已退出',
            }
            
            for logtype in log_types:
                try:
                    hand = win32evtlog.OpenEventLog('localhost', logtype)
                    total = win32evtlog.GetNumberOfEventLogRecords(hand)
                    
                    # 读取最近的500条日志记录
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(hand, flags, 0, 500)
                    
                    for event in events:
                        event_id = event.EventID & 0xFFFF  # 获取事件ID（去除高位标志位）
                        
                        # 根据日志类型和事件ID进行过滤
                        if (logtype == 'Security' and event_id in security_event_ids) or \
                           (event.EventType in [win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE]):
                            
                            # 提取事件描述
                            try:
                                description = ""
                                if event.StringInserts and len(event.StringInserts) > 0:
                                    description = " | ".join([str(i) for i in event.StringInserts if i])
                                else:
                                    description = f"事件ID: {event_id}"
                                
                                # 添加事件ID的描述（如果是已知的安全事件）
                                if logtype == 'Security' and event_id in security_event_ids:
                                    description = f"{security_event_ids[event_id]} - {description}"
                                
                                # 确定风险级别
                                risk_level = 'high' if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE or \
                                                      (logtype == 'Security' and event_id in [4625, 4740, 1102, 4720, 4738]) \
                                             else 'medium'
                                
                                # 修复时间戳处理问题
                                try:
                                    # 将pywintypes.datetime转换为Python datetime
                                    if hasattr(event.TimeGenerated, 'timestamp'):
                                        # 如果TimeGenerated已经有timestamp方法
                                        timestamp = event.TimeGenerated.timestamp()
                                        time_str = datetime.fromtimestamp(timestamp).isoformat()
                                    else:
                                        # 直接使用当前时间作为备选
                                        time_str = datetime.now().isoformat()
                                except Exception as e:
                                    logger.error(f"时间戳转换失败: {str(e)}")
                                    time_str = datetime.now().isoformat()
                                
                                findings.append({
                                    'type': 'security_event',
                                    'source': logtype,
                                    'event_id': event_id,
                                    'description': description[:500],  # 限制描述长度
                                    'risk_level': risk_level,
                                    'timestamp': time_str
                                })
                            except Exception as e:
                                logger.error(f"处理事件数据失败: {str(e)}")
                    
                    win32evtlog.CloseEventLog(hand)
                except Exception as e:
                    logger.error(f"读取{logtype}日志失败: {str(e)}")
            
            # 按时间戳排序，最新的事件在前
            findings.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # 限制返回的事件数量
            return findings[:100]  # 最多返回100条事件
            
        except Exception as e:
            logger.error(f"分析Windows日志失败: {str(e)}")
            return []

    def _analyze_linux_logs(self):
        """分析Linux日志"""
        findings = []
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            if any(keyword in line.lower() for keyword in ['error', 'failed', 'denied', 'unauthorized']):
                                findings.append({
                                    'type': 'security_event',
                                    'description': line.strip(),
                                    'risk_level': 'high' if 'error' in line.lower() else 'medium',
                                    'timestamp': datetime.now().isoformat()
                                })
                except Exception as e:
                    logger.error(f"分析Linux日志 {log_file} 失败: {str(e)}")
        return findings

    def send_data_to_server(self):
        """发送数据到服务器"""
        try:
            # 获取日志分析结果
            log_findings = self.analyze_logs()
            
            data = {
                'host_info': self.host_info,
                'processes': self.get_process_info(),
                'services': self.get_service_info(),
                'security_findings': log_findings  # 添加security_findings字段以匹配服务器期望
            }
            
            response = requests.post(
                f"{self.server_url}/api/hosts/update",
                json=data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info("数据成功发送到服务器")
            else:
                logger.error(f"发送数据失败: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"发送数据到服务器失败: {str(e)}")

def main():
    server_url = "http://localhost:5000"  # 替换为实际的服务器地址
    agent = HostAgent(server_url)
    agent.send_data_to_server()

if __name__ == "__main__":
    main()