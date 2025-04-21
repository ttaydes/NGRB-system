from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import hashlib
import magic
import yara
import pandas as pd
from datetime import datetime
from extensions import db
from models.file import File
import requests
import json
import tempfile
import time

bp = Blueprint('file', __name__, url_prefix='/api/file')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'php', 'jsp', 'asp', 'aspx', 'js', 'py', 'sh', 'bat', 'ps1'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):

    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_file(file_path,original_filename):
    """分析单个文件"""
    try:
        # 获取文件基本信息
        file_size = os.path.getsize(file_path)
        file_type = magic.from_file(file_path)
        
        # 计算SHA256
        sha256 = calculate_sha256(file_path)
        
        # 使用YARA规则进行检测
        rules = yara.compile('rules/backdoor_shamanic.yar')
        matches = rules.match(file_path)
        
        # 确定威胁等级
        threat_level = '低危'
        
        if matches:
            for match in matches:
                severity = match.meta.get('severity', 'low')
                if severity == 'high':
                    threat_level = '高危'
                elif severity == 'medium' and threat_level != '高危':
                    threat_level = '中危'
             
        
        # 保存分析结果到数据库
        file_record = File(
            file_name=original_filename,
            sha256=sha256,
            file_type=file_type,
            file_size=file_size,
            threat_level=threat_level,
            detection_time=datetime.now()
        )
        db.session.add(file_record)
        db.session.commit()
        
        return {
            'success': True,
            'data': {
                'filename': original_filename,
                'sha256': sha256,
                'fileType': file_type,
                'fileSize': file_size,
                'threatLevel': threat_level,
                'detectionTime': datetime.now().isoformat()
            }
        }
    except Exception as e:
        return {
            'success': False,
            'message': str(e)
        }

@bp.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有文件上传'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '未选择文件'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': '不支持的文件类型'}), 400
    
    try:
        timestamp = int(time.time())
        original_filename = file.filename 
        ext = os.path.splitext(original_filename)[1]
        filename = secure_filename(f"{timestamp}{ext}")
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        result = analyze_file(file_path,original_filename)
        
        # 清理上传的文件
        os.remove(file_path)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@bp.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    if 'files[]' not in request.files:
        return jsonify({'success': False, 'message': '没有文件上传'}), 400
    
    files = request.files.getlist('files[]')
    if not files:
        return jsonify({'success': False, 'message': '未选择文件'}), 400
    
    results = []
    for file in files:
        if file.filename == '':
            continue
        
        if not allowed_file(file.filename):
            results.append({
                'filename': file.filename,
                'success': False,
                'message': '不支持的文件类型'
            })
            continue
        
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            result = analyze_file(file_path)
            results.append({
                'filename': file.filename,
                'success': result['success'],
                'data': result.get('data'),
                'message': result.get('message')
            })
            
            # 清理上传的文件
            os.remove(file_path)
        except Exception as e:
            results.append({
                'filename': file.filename,
                'success': False,
                'message': str(e)
            })
    
    return jsonify({
        'success': True,
        'data': results
    })

@bp.route('/history', methods=['GET'])
def get_history():
    try:
        files = File.query.order_by(File.detection_time.desc()).all()
        return jsonify([{
            'filename': file.file_name,
            'sha256': file.sha256,
            'fileType': file.file_type,
            'fileSize': file.file_size,
            'threatLevel': file.threat_level,
            'detectionTime': file.detection_time.isoformat()
        } for file in files])
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@bp.route('/export-report', methods=['POST'])
def export_report():
    try:
        data = request.get_json()
        results = data.get('results', [])
        
        # 创建临时Excel文件
        with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as tmp:
            df = pd.DataFrame(results)
            with pd.ExcelWriter(tmp.name, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='分析结果', index=False)
                
                # 设置列宽
                worksheet = writer.sheets['分析结果']
                worksheet.set_column('A:A', 20)  # 文件名
                worksheet.set_column('B:B', 64)  # SHA256
                worksheet.set_column('C:C', 15)  # 文件类型
                worksheet.set_column('D:D', 10)  # 大小
                worksheet.set_column('E:E', 10)  # 威胁等级
                worksheet.set_column('F:F', 20)  # 检测时间
            
            # 发送文件
            return send_file(
                tmp.name,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name='file_analysis_report.xlsx'
            )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500