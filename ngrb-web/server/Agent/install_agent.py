import os
import sys
import platform
import subprocess
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import logging
from pathlib import Path

class AgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "HostSecurityAgent"
    _svc_display_name_ = "Host Security Agent Service"
    _svc_description_ = "Host Security Information Collection Agent"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_alive = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_alive = False

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        while self.is_alive:
            try:
                # 运行agent主程序
                subprocess.run([sys.executable, 'host_agent.py'], check=True)
            except Exception as e:
                logging.error(f"Agent运行错误: {str(e)}")
            # 等待5分钟后再次运行
            win32event.WaitForSingleObject(self.stop_event, 300000)

def install_agent():
    """安装agent"""
    try:
        # 获取当前目录
        current_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        
        # 安装依赖
        #subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        
        if platform.system() == 'Windows':
            # 安装Windows服务
            win32serviceutil.InstallService(
                pythonClassString = 'install_agent.AgentService',
                serviceName = 'HostSecurityAgent',
                displayName = 'Host Security Agent Service',
                description = 'Host Security Information Collection Agent',
                startType = win32service.SERVICE_AUTO_START
            )
            print("Windows服务安装成功")
        else:
            # 创建Linux系统服务
            service_content = f"""[Unit]
Description=Host Security Agent Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={current_dir}
ExecStart={sys.executable} {current_dir}/host_agent.py
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
"""
            with open('/etc/systemd/system/host-security-agent.service', 'w') as f:
                f.write(service_content)
            
            # 启用并启动服务
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', 'host-security-agent'], check=True)
            subprocess.run(['systemctl', 'start', 'host-security-agent'], check=True)
            print("Linux服务安装成功")
            
    except Exception as e:
        print(f"安装失败: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        install_agent()
    else:
        win32serviceutil.HandleCommandLine(AgentService) 