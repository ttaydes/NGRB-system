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
import win32api
import win32con
from pathlib import Path

# 获取脚本所在目录的绝对路径
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(SCRIPT_DIR / 'host_agent.log'),
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
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time', 'cmdline']):
            try:
                pinfo = proc.info
                processes.append({
                    'process_name': pinfo['name'],
                    'pid': pinfo['pid'],
                    'user': pinfo['username'],
                    'cpu_usage': pinfo['cpu_percent'],
                    'memory_usage': pinfo['memory_percent'],
                    'start_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo['create_time'] else None,
                    'command_line': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else None
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
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
            import wmi
            c = wmi.WMI()
            for service in c.Win32_Service():
                services.append({
                    'service_name': service.Name,
                    'status': 'running' if service.State == 'Running' else 'stopped',
                    'description': service.Description or '',
                    'start_type': service.StartMode
                })
        except Exception as e:
            logger.error(f"获取Windows服务信息失败: {str(e)}")
            # 备用方案：使用sc命令
            try:
                import subprocess
                result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                     capture_output=True, text=True)
                current_service = {}
                for line in result.stdout.split('\n'):
                    if 'SERVICE_NAME:' in line:
                        if current_service:
                            services.append(current_service)
                        current_service = {
                            'service_name': line.split('SERVICE_NAME:')[1].strip(),
                            'status': 'stopped',
                            'description': ''
                        }
                    elif 'STATE' in line:
                        current_service['status'] = 'running' if 'RUNNING' in line else 'stopped'
                if current_service:
                    services.append(current_service)
            except Exception as e2:
                logger.error(f"备用方案获取Windows服务信息也失败: {str(e2)}")
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

    def scan_ports(self):
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
            import win32evtlog
            server = 'localhost'
            logtype = 'Security'
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                if event.EventType in [win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE]:
                    findings.append({
                        'type': 'security_event',
                        'description': event.StringInserts[0] if event.StringInserts else 'Unknown event',
                        'risk_level': 'high' if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE else 'medium',
                        'timestamp': datetime.fromtimestamp(event.TimeGenerated).isoformat()
                    })
        except Exception as e:
            logger.error(f"分析Windows日志失败: {str(e)}")
        return findings

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
            data = {
                'host_info': self.host_info,
                'processes': self.get_process_info(),
                'services': self.get_service_info(),
                'port_scan': self.scan_ports(),
                'security_findings': self.analyze_logs()
            }
            
            # 打印调试信息
            logger.info(f"正在发送数据到服务器: {self.server_url}")
            logger.info(f"数据内容: {json.dumps(data, indent=2)}")
            
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
    # 修改为你的实际服务器地址和端口
    server_url = "http://127.0.0.1:5000"  # Flask-SocketIO默认使用5000端口
    logger.info(f"启动agent，服务器地址: {server_url}")
    agent = HostAgent(server_url)
    agent.send_data_to_server()

if __name__ == "__main__":
    main()