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
import ast

from loguru import logger
bp = Blueprint('file', __name__, url_prefix='/api/file')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'php', 'jsp', 'asp', 'aspx', 'js', 'py', 'sh', 'bat', 'ps1','rar','zip','7z','docx','doc','xls','xlsx'}

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
def weibu_analysis(sha256,filename,original_filename,file_path):
    upload_url = 'https://api.threatbook.cn/v3/file/upload'
    upload_params = {
        'apikey': '31da4ad48e1f4b3d9fcf1c60a385121527a67eb319dd4341a6c74794ef474e0e',
        'sandbox_type': 'win7_sp1_enx86_office2013',
        'run_time': 60
    }
    files = {
    'file' : (filename, open(os.path.join(file_path), 'rb'))
    }   
    response = requests.post(upload_url, data=upload_params,files=files)
    if response.status_code == 200:
        logger.info(f"============微步情报上传文件成功============")
    else:
        logger.info(f"============微步情报上传文件失败============")

    #接入微步情报
    # 获取微步情报API密钥
    url = 'https://api.threatbook.cn/v3/file/report';
    params = {
        'apikey': '31da4ad48e1f4b3d9fcf1c60a385121527a67eb319dd4341a6c74794ef474e0e',
        'sandbox_type': 'win7_sp1_enx86_office2013',
        'resource': sha256,
    }       
    
    time.sleep(10)
    

    response = requests.get(url,params=params)
    return response.json()

def yara_analysis(file_path):
    rules = yara.compile('rules/backdoor_shamanic.yar')
    matches = rules.match(file_path)
    return matches

def analyze_file(file_path,original_filename,filename):
    """分析单个文件"""
    try:
        weibu_analysis_result = {}
        yara_analysis_result = {}
        threat_level = ''
        # 获取文件基本信息
        file_size = os.path.getsize(file_path)  
        file_type = magic.from_file(file_path)
        
        # 计算SHA256
        sha256 = calculate_sha256(file_path)
        #yara分析
        try:
            yara_result = yara_analysis(file_path)
    
            if yara_result:
                for match in yara_result:
                    yara_check_info =  match.rule
                    yara_result_malware_type = match.meta.get("malware_type", "unknown")
                    yara_result_malware_family = match.meta.get("malware_family", "unknown")
                    yara_result_threat_level = match.meta.get("threat_level", "unknown")

                yara_analysis_result = {
                    'check_info': yara_check_info,
                    'malware_type': yara_result_malware_type,
                    'malware_family': yara_result_malware_family,
                    'threat_level': yara_result_threat_level
                }
        except Exception as e:
            logger.info(f"============yara分析失败{e}============")
        # 调用微步情报API   
        try:
            weibu_result = weibu_analysis(sha256,filename,original_filename,file_path)
            logger.info(f"============微步情报API结果: {weibu_result}")
            if weibu_result['response_code'] == 0:

                try:
                    weibu_result_summary = weibu_result['data']['summary']
                    if weibu_result_summary:
                        weibu_result_md5 = weibu_result_summary['md5']
                        weibu_result_tags = weibu_result_summary['tag']
                        weibu_result_malware_family = weibu_result_summary['malware_family']
                        weibu_result_malware_type = weibu_result_summary['malware_type']
                        threat_level = weibu_result_summary['threat_level']
                        weibu_result_submit_time = weibu_result_summary['submit_time']


                    if "multiengines" in weibu_result['data']:
                        weibu_result_multiengines = weibu_result['data']['multiengines']
                    else:
                        weibu_result_multiengines = {}

                    if "network" in weibu_result['data']:
                        weibu_result_network = weibu_result['data']['network']
                    else:
                        weibu_result_network = {}

                    if "strings" in weibu_result['data']:
                        weibu_result_strings = weibu_result['data']['strings']
                    else:
                        weibu_result_strings = {}

                except Exception as e:
                    logger.info(f"============微步情报API结果解析失败{e}============")
                weibu_analysis_result = {
                    'md5': weibu_result_md5,
                    'tag': weibu_result_tags,
                    'malware_family': weibu_result_malware_family,
                    'malware_type': weibu_result_malware_type,
                    'threat_level': threat_level,
                    'submit_time': weibu_result_submit_time,
                    'multiengines': weibu_result_multiengines,
                    'network': weibu_result_network,
                    'strings': weibu_result_strings
                }   
        except Exception as e:
            logger.info(f"============微步情报API结果解析失败{e}============")

        

      
        if yara_analysis_result and weibu_analysis_result:
            #比较yara和 api的threat_level   为 clean suspicious malicious 三种标准
            if yara_analysis_result['threat_level'] == 'clean' and weibu_analysis_result['threat_level'] == 'clean':
                threat_level = 'clean'
            elif yara_analysis_result['threat_level'] == 'suspicious' or weibu_analysis_result['threat_level'] == 'suspicious':
                threat_level = 'suspicious'
            elif yara_analysis_result['threat_level'] == 'malicious' or weibu_analysis_result['threat_level'] == 'malicious':
                threat_level = 'malicious'

        else:
            threat_level = weibu_analysis_result['threat_level']


        #检查该sha256是否在数据库中存在
        file_record = File.query.filter_by(sha256=sha256).first()
        if file_record:
            return {
                'success': True,
                'data': file_record.to_dict()
            }
        
        #如果数据库中不存在，则保存分析结果到数据库
        if not file_record:
            # 保存分析结果到数据库
            file_record = File(
                file_name=original_filename,
                sha256=sha256,
                md5=weibu_result_md5 if weibu_result_md5 else '',
                file_type=file_type,
                file_size=file_size,
                threat_level=threat_level,
                yara_result=str(yara_analysis_result),   
                api_result=str(weibu_analysis_result),
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
                    'yaraResult': yara_analysis_result,
                    'apiResult': weibu_analysis_result,
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
        logger.info(f"============原始文件名: {original_filename}")
        ext = os.path.splitext(original_filename)[1]
        filename = secure_filename(f"{timestamp}{ext}")
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        result = analyze_file(file_path,original_filename,filename)
        
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
            
            result = analyze_file(file_path,file.filename,filename)
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
            'yaraResult': json.dumps(ast.literal_eval(file.yara_result)),
            'apiResult': json.dumps(ast.literal_eval(file.api_result)),
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
                worksheet.set_column('C:C', 32)  # md5
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