from flask import Blueprint, request, jsonify
from datetime import datetime
from extensions import db
from models.host import Host
import subprocess
import os
import json
import threading
import time

bp = Blueprint('host', __name__)

# 存储正在进行的流量捕获任务
capture_tasks = {}

@bp.route('/api/hosts', methods=['GET'])
def get_hosts():
    try:
        hosts = Host.query.all()
        return jsonify({
            'success': True,
            'data': [host.to_dict() for host in hosts]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/hosts/<int:host_id>', methods=['GET'])
def get_host_detail(host_id):
    try:
        host = Host.query.get_or_404(host_id)
        return jsonify({
            'success': True,
            'data': host.to_dict()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/hosts/capture', methods=['POST'])
def start_capture():
    try:
        data = request.get_json()
        host_id = data.get('host_id')
        duration = data.get('duration', 5)
        filter_str = data.get('filter', '')
        save_path = data.get('save_path', 'captures')
        
        if not host_id:
            return jsonify({
                'success': False,
                'message': '缺少主机ID'
            }), 400
        
        # 确保保存目录存在
        if not os.path.exists(save_path):
            os.makedirs(save_path)
        
        # 生成文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"capture_{host_id}_{timestamp}.pcap"
        filepath = os.path.join(save_path, filename)
        
        # 构建tcpdump命令
        cmd = ['tcpdump', '-i', 'any']
        if filter_str:
            cmd.extend(['-f', filter_str])
        cmd.extend(['-w', filepath])
        
        # 启动捕获进程
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # 存储任务信息
        task_id = f"{host_id}_{timestamp}"
        capture_tasks[task_id] = {
            'process': process,
            'start_time': datetime.now(),
            'duration': duration,
            'filepath': filepath,
            'host_id': host_id
        }
        
        # 启动监控线程
        threading.Thread(
            target=monitor_capture,
            args=(task_id,),
            daemon=True
        ).start()
        
        return jsonify({
            'success': True,
            'message': '开始捕获流量',
            'data': {
                'task_id': task_id,
                'filepath': filepath
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

def monitor_capture(task_id):
    task = capture_tasks.get(task_id)
    if not task:
        return
    
    start_time = task['start_time']
    duration = task['duration']
    process = task['process']
    
    try:
        # 等待指定的时间
        time.sleep(duration * 60)
        
        # 终止捕获进程
        process.terminate()
        process.wait()
        
        # 清理任务
        del capture_tasks[task_id]
        
        # 这里可以添加文件处理逻辑，例如上传到服务器等
        
    except Exception as e:
        print(f"捕获任务 {task_id} 监控出错: {str(e)}")
        if task_id in capture_tasks:
            del capture_tasks[task_id]

@bp.route('/api/hosts/capture/<task_id>', methods=['GET'])
def get_capture_status(task_id):
    if task_id not in capture_tasks:
        return jsonify({
            'success': False,
            'message': '任务不存在'
        }), 404
    
    task = capture_tasks[task_id]
    elapsed = (datetime.now() - task['start_time']).total_seconds() / 60
    
    return jsonify({
        'success': True,
        'data': {
            'status': 'running',
            'elapsed': round(elapsed, 2),
            'duration': task['duration'],
            'filepath': task['filepath']
        }
    })

@bp.route('/api/hosts/capture/<task_id>', methods=['DELETE'])
def stop_capture(task_id):
    if task_id not in capture_tasks:
        return jsonify({
            'success': False,
            'message': '任务不存在'
        }), 404
    
    task = capture_tasks[task_id]
    try:
        task['process'].terminate()
        task['process'].wait()
        del capture_tasks[task_id]
        
        return jsonify({
            'success': True,
            'message': '已停止捕获'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500