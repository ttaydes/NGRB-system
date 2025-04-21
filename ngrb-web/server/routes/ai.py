from flask import Blueprint, request, jsonify
import requests
import json
from datetime import datetime

bp = Blueprint('ai', __name__)

# DeepSeek API配置
DEEPSEEK_API_KEY = "sk-5606002ef9d24c6aa36a3c2c1ca8d9ea"
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

def analyze_with_deepseek(content, analysis_type):
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # 根据分析类型构建不同的提示词
    prompts = {
        'traffic': f"""请分析以下网络流量数据，识别潜在的安全威胁：
{content}

请提供：
1. 简要分析摘要
2. 发现的威胁类型和严重程度
3. 具体的建议措施""",
        
        'file': f"""请分析以下文件特征，判断是否为恶意文件：
{content}

请提供：
1. 文件类型和特征分析
2. 潜在的威胁类型
3. 处理建议""",
        
        'host': f"""请分析以下主机安全日志，评估安全状态：
{content}

请提供：
1. 安全状态评估
2. 发现的安全问题
3. 加固建议""",
        
        'threat': f"""请分析以下威胁情报，评估其影响：
{content}

请提供：
1. 威胁概述
2. 影响范围评估
3. 应对建议"""
    }
    
    prompt = prompts.get(analysis_type, prompts['traffic'])
    
    data = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": "你是一个专业的安全分析师，擅长分析各种安全威胁和提供解决方案。"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        
        # 解析AI返回的结果
        ai_response = result['choices'][0]['message']['content']
        
        # 将AI返回的文本解析为结构化数据
        # 这里需要根据实际返回格式进行调整
        return {
            'summary': extract_summary(ai_response),
            'threats': extract_threats(ai_response),
            'recommendations': extract_recommendations(ai_response),
            'confidence': 85  # 示例置信度
        }
    except Exception as e:
        print(f"DeepSeek API调用失败: {str(e)}")
        return None

def extract_summary(text):
    # 简单的文本解析逻辑，实际应用中可能需要更复杂的解析
    lines = text.split('\n')
    for line in lines:
        if '摘要' in line or '概述' in line:
            return line.strip()
    return "无法提取摘要"

def extract_threats(text):
    threats = []
    lines = text.split('\n')
    current_threat = None
    
    for line in lines:
        if '威胁' in line or '问题' in line:
            if current_threat:
                threats.append(current_threat)
            current_threat = {'type': line.strip(), 'description': '', 'severity': '中'}
        elif current_threat and line.strip():
            if '严重程度' in line:
                current_threat['severity'] = line.split('：')[-1].strip()
            else:
                current_threat['description'] += line.strip() + ' '
    
    if current_threat:
        threats.append(current_threat)
    
    return threats

def extract_recommendations(text):
    recommendations = []
    lines = text.split('\n')
    current_rec = None
    
    for line in lines:
        if '建议' in line or '措施' in line:
            if current_rec:
                recommendations.append(current_rec)
            current_rec = {'title': line.strip(), 'description': '', 'steps': []}
        elif current_rec:
            if line.strip().startswith(('1.', '2.', '3.', '4.', '5.')):
                current_rec['steps'].append(line.strip()[2:].strip())
            elif line.strip():
                current_rec['description'] += line.strip() + ' '
    
    if current_rec:
        recommendations.append(current_rec)
    
    return recommendations

@bp.route('/api/ai/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    content = data.get('content')
    analysis_type = data.get('type', 'traffic')
    
    if not content:
        return jsonify({'success': False, 'message': '请提供需要分析的内容'}), 400
    
    result = analyze_with_deepseek(content, analysis_type)
    print(result)
    if result:
        return jsonify({
            'success': True,
            'data': result
        })
    else:
        return jsonify({
            'success': False,
            'message': 'AI分析失败'
        }), 500