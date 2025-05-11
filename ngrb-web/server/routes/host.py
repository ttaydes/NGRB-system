from flask import Blueprint, jsonify, request
from models.host import Host, ProcessInfo, ServiceInfo, SecurityScan
from extensions import db
import subprocess
import json
import os
from datetime import datetime

bp = Blueprint('host', __name__,url_prefix='/api')

@bp.route('/hosts', methods=['GET'])
def get_hosts():
    hosts = Host.query.all()
    return jsonify([{
        'id': host.id,
        'hostname': host.hostname,
        'ip_address': host.ip_address,
        'os_type': host.os_type,
        'status': host.status
    } for host in hosts])

@bp.route('/hosts/update', methods=['POST'])
def update_host_info():
    """处理agent发送的主机信息更新"""
    data = request.json
    
    # 更新或创建主机信息
    host = Host.query.filter_by(ip_address=data['host_info']['ip_address']).first()
    if not host:
        host = Host(**data['host_info'])
        db.session.add(host)
    else:
        for key, value in data['host_info'].items():
            setattr(host, key, value)
    
    # 更新进程信息
    ProcessInfo.query.filter_by(host_id=host.id).delete()
    for process in data['processes']:
        process_info = ProcessInfo(host_id=host.id, **process)
        db.session.add(process_info)
    
    # 更新服务信息
    ServiceInfo.query.filter_by(host_id=host.id).delete()
    for service in data['services']:
        service_info = ServiceInfo(host_id=host.id, **service)
        db.session.add(service_info)
    
    # 创建安全扫描记录
    scan = SecurityScan(
        host_id=host.id,
        scan_type='agent_report',
        status='completed',
        findings=data['security_findings'],
        risk_level='high' if any(f['risk_level'] == 'high' for f in data['security_findings']) else 'medium'
    )
    db.session.add(scan)
    
    try:
        db.session.commit()
        return jsonify({'message': 'Host information updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bp.route('/hosts/<int:host_id>/scan', methods=['POST'])
def start_host_scan(host_id):
    host = Host.query.get_or_404(host_id)
    scan_type = request.json.get('scan_type', 'basic')
    
    # 创建新的扫描任务
    scan = SecurityScan(
        host_id=host_id,
        scan_type=scan_type,
        status='running'
    )
    db.session.add(scan)
    db.session.commit()
    
    try:
        # 异步执行扫描任务
        if scan_type == 'basic':
            # 使用fscan进行基础扫描
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            result = subprocess.run(
                ['E:\\TOOL\\ShenTouCeShi\\one-fox\\gui_scan\\fscan\\fscan64.exe', '-h', host.ip_address],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                startupinfo=startupinfo
            )
            
            if result.returncode == 0:
                scan.findings = {'fscan_output': result.stdout}
            else:
                scan.findings = {
                    'error': f'Scan failed with return code {result.returncode}',
                    'stderr': result.stderr
                }
                scan.status = 'failed'
        
        
        if scan.status != 'failed':
            scan.status = 'completed'
        db.session.commit()
        
        return jsonify({'message': 'Scan completed', 'scan_id': scan.id})
    except Exception as e:
        scan.status = 'failed'
        scan.findings = {'error': str(e)}
        db.session.commit()
        return jsonify({'error': str(e)}), 500

@bp.route('/hosts/<int:host_id>/processes', methods=['GET'])
def get_processes(host_id):
    processes = ProcessInfo.query.filter_by(host_id=host_id).all()
    return jsonify([{
        'id': p.id,
        'process_name': p.process_name,
        'pid': p.pid,
        'connections': p.connections,
        'user': p.user,
        'cpu_usage': p.cpu_usage,
        'memory_usage': p.memory_usage
    } for p in processes])

@bp.route('/hosts/<int:host_id>/services', methods=['GET'])
def get_services(host_id):
    services = ServiceInfo.query.filter_by(host_id=host_id).all()
    return jsonify([{
        'id': s.id,
        'service_name': s.service_name,
        'status': s.status,
        'port': s.port,
        'protocol': s.protocol,
        'start_type': s.start_type,
        'display_name': s.display_name,
        'description': s.description
    } for s in services])



@bp.route('/hosts/<int:host_id>/scans', methods=['GET'])    
def get_scans(host_id):
    scans = SecurityScan.query.filter_by(host_id=host_id).all()
    return jsonify([{
        'id': s.id,
        'scan_type': s.scan_type,
        'status': s.status,
        'findings': s.findings,
        'risk_level': s.risk_level,
        'scan_time': s.scan_time
    } for s in scans])



def analyze_logs(host):
    # 实现日志分析逻辑
    pass