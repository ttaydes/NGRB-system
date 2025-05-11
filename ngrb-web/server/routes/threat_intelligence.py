from flask import Blueprint, request, jsonify
from extensions import db
from models.threat_intelligence import (
    ThreatCategory, BaseThreatIntel, Top10Vulnerability, WebshellAttack, 
    Malware, CVE, POC, MaliciousIP, C2Server, SensitiveInfo,Tool
)
from datetime import datetime

bp = Blueprint('threat_intelligence', __name__, url_prefix='/api/threat-intel')

# 获取所有威胁情报
@bp.route('', methods=['GET'])
def get_all_threat_intel():
    try:
        # 获取查询参数
        category_id = request.args.get('category_id', type=int)
        intel_type = request.args.get('type')
        is_active = request.args.get('is_active')
        
        # 构建查询条件
        filters = {}
        if category_id:
            filters['category_id'] = category_id
        if is_active is not None:
            filters['is_active'] = is_active == 'true'
            
        # 根据类型获取不同表的数据
        result = []
        if intel_type == 'top10':
            items = Top10Vulnerability.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'webshell':
            items = WebshellAttack.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'malware':
            items = Malware.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'cve':
            items = CVE.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'poc':
            items = POC.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'ip':
            items = MaliciousIP.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'c2':
            items = C2Server.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'sensitive':
            items = SensitiveInfo.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        elif intel_type == 'tool':
            items = Tool.query.filter_by(**filters).all()
            result = [item.to_dict() for item in items]
        else:
            # 如果没有指定类型，则获取所有类型的数据
            result = []
            for model in [Top10Vulnerability, WebshellAttack, Malware, CVE, POC, MaliciousIP, C2Server, SensitiveInfo,Tool]:
                items = model.query.filter_by(**filters).all()
                result.extend([item.to_dict() for item in items])
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 获取威胁情报类别
@bp.route('/categories', methods=['GET'])
def get_categories():
    try:
        categories = ThreatCategory.query.all()
        return jsonify({
            'success': True,
            'data': [category.to_dict() for category in categories]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 添加威胁情报类别
@bp.route('/categories', methods=['POST'])
def add_category():
    try:
        data = request.get_json()
        category = ThreatCategory(
            name=data.get('name'),
            code=data.get('code'),
            description=data.get('description')
        )
        db.session.add(category)
        db.session.commit()
        return jsonify({
            'success': True,
            'data': category.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 添加威胁情报
@bp.route('', methods=['POST'])
def add_threat_intel():
    try:
        data = request.get_json()
        intel_type = data.get('type')
        category_id = data.get('category_id')
        
        # 基础字段
        base_fields = {
            'name': data.get('name'),
            'description': data.get('description'),
            'source': data.get('source'),
            'confidence': data.get('confidence'),
            'severity': data.get('severity'),
            'is_active': data.get('is_active', True),
            'pattern_content': data.get('pattern_content'),
            'match_location': data.get('match_location'),
            'is_regex': data.get('is_regex', False),
            'tags': data.get('tags'),
            'reference': data.get('reference'),
            'category_id': category_id
        }
        
        # 根据类型创建不同的情报对象
        if intel_type == 'top10':
            intel = Top10Vulnerability(
                **base_fields,
                vulnerability_type=data.get('vulnerability_type'),
                cwe_id=data.get('cwe_id'),
                affected_systems=data.get('affected_systems'),
                mitigation=data.get('mitigation')
            )
        elif intel_type == 'webshell':
            intel = WebshellAttack(
                **base_fields,
                shell_type=data.get('shell_type'),
                language=data.get('language'),
                file_extension=data.get('file_extension'),
                detection_method=data.get('detection_method')
            )
        elif intel_type == 'malware':
            intel = Malware(
                **base_fields,
                malware_type=data.get('malware_type'),
                file_hash=data.get('file_hash'),
                file_type=data.get('file_type'),
                behavior=data.get('behavior')
            )
        elif intel_type == 'cve':
            intel = CVE(
                **base_fields,
                cve_id=data.get('cve_id'),
                cvss_score=data.get('cvss_score'),
                affected_products=data.get('affected_products'),
                patch_info=data.get('patch_info')
            )
        elif intel_type == 'poc':
            intel = POC(
                **base_fields,
                poc_content=data.get('poc_content'),
                target_system=data.get('target_system'),
                exploit_method=data.get('exploit_method')
            )
        elif intel_type == 'ip':
            intel = MaliciousIP(
                **base_fields,
                ip_address=data.get('ip_address'),
                ip_type=data.get('ip_type')
            )
        elif intel_type == 'c2':
            intel = C2Server(
                **base_fields,
                ip_address=data.get('ip_address'),
                domain=data.get('domain'),
                port=data.get('port'),
                protocol=data.get('protocol')
            )
        elif intel_type == 'sensitive':
            intel = SensitiveInfo(
                **base_fields,
                info_type=data.get('info_type')
            )
        elif intel_type == 'tool':
            intel = Tool(
                **base_fields,
                tool_name=data.get('tool_name'),
                tool_type=data.get('tool_type')
            )
        else:
            return jsonify({
                'success': False,
                'message': '不支持的情报类型'
            }), 400
        
        db.session.add(intel)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': intel.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 获取单个威胁情报
@bp.route('/<int:intel_id>', methods=['GET'])
def get_threat_intel(intel_id):
    try:
        # 尝试在各个表中查找
        for model in [Top10Vulnerability, WebshellAttack, Malware, CVE, POC, MaliciousIP, C2Server, SensitiveInfo,Tool]:
            intel = model.query.get(intel_id)
            if intel:
                return jsonify({
                    'success': True,
                    'data': intel.to_dict()
                })
        
        return jsonify({
            'success': False,
            'message': '找不到指定的威胁情报'
        }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 更新威胁情报
@bp.route('/<int:intel_id>', methods=['PUT'])
def update_threat_intel(intel_id):
    try:
        data = request.get_json()
        intel_type = data.get('type')
        
        # 根据类型和ID查找对应的情报
        intel = None
        if intel_type == 'top10':
            intel = Top10Vulnerability.query.get(intel_id)
        elif intel_type == 'webshell':
            intel = WebshellAttack.query.get(intel_id)
        elif intel_type == 'malware':
            intel = Malware.query.get(intel_id)
        elif intel_type == 'cve':
            intel = CVE.query.get(intel_id)
        elif intel_type == 'poc':
            intel = POC.query.get(intel_id)
        elif intel_type == 'ip':
            intel = MaliciousIP.query.get(intel_id)
        elif intel_type == 'c2':
            intel = C2Server.query.get(intel_id)
        elif intel_type == 'sensitive':
            intel = SensitiveInfo.query.get(intel_id)
        elif intel_type == 'tool':
            intel = Tool.query.get(intel_id)
        if not intel:
            return jsonify({
                'success': False,
                'message': f'未找到ID为{intel_id}的{intel_type}类型情报'
            }), 404
        
        # 更新情报字段
        for key, value in data.items():
            if key != 'type' and hasattr(intel, key):
                setattr(intel, key, value)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': intel.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 删除威胁情报
@bp.route('/<int:intel_id>', methods=['DELETE'])
def delete_threat_intel(intel_id):
    try:
        # 尝试在各个表中查找并删除
        for model in [Top10Vulnerability, WebshellAttack, Malware, CVE, POC, MaliciousIP, C2Server, SensitiveInfo,Tool]:
            intel = model.query.get(intel_id)
            if intel:
                db.session.delete(intel)
                db.session.commit()
                return jsonify({
                    'success': True,
                    'message': '删除成功'
                })
        
        return jsonify({
            'success': False,
            'message': '找不到指定的威胁情报'
        }), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# # 搜索威胁情报
# @bp.route('/search', methods=['GET'])
# def search_threat_intel():
#     try:
#         keyword = request.args.get('keyword', '')
        
#         if not keyword:
#             return jsonify({
#                 'success': False,
#                 'message': '请提供搜索关键词'
#             }), 400
        
#         # 在各个表中搜索
#         result = []
#         for model in [Top10Vulnerability, WebshellAttack, Malware, CVE, POC, MaliciousIP, C2Server, SensitiveInfo,Tool]:
#             items = model.query.filter(
#                 (model.name.like(f'%{keyword}%')) | 
#                 (model.description.like(f'%{keyword}%'))
#             ).all()
#             result.extend([item.to_dict() for item in items])
        
#         return jsonify({
#             'success': True,
#             'data': result
#         })
#     except Exception as e:
#         return jsonify({
#             'success': False,
#             'message': str(e)
#         }), 500
