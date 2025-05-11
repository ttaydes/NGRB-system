<template>
  <div class="threat-intel-container">
    <!-- 添加顶部操作栏 -->
    <div class="operation-bar" style="margin-bottom: 20px">
      <el-button type="primary" @click="dialogVisible = true">
        <el-icon><Plus /></el-icon>添加情报
      </el-button>
      
      <!-- 添加类别筛选 -->
      <el-select 
        v-model="filterCategory" 
        placeholder="按类别筛选" 
        clearable 
        style="margin-left: 15px; width: 150px"
        @change="loadThreatIntelList"
      >
        <el-option
          v-for="category in categories"
          :key="category.id"
          :label="category.name"
          :value="category.id"
        />
      </el-select>
      
      <!-- 添加类型筛选 -->
      <el-select 
        v-model="filterType" 
        placeholder="按类型筛选" 
        clearable 
        style="margin-left: 15px; width: 150px"
        @change="loadThreatIntelList"
      >
        <el-option
          v-for="(label, value) in typeOptions"
          :key="value"
          :label="label"
          :value="value"
        />
      </el-select>
    </div>

    <!-- 情报管理表格 -->
    <el-table :data="threatIntelList" style="width: 100%">
      <el-table-column prop="type" label="类型">
        <template #default="{ row }">
          <el-tag :type="getTypeTag(row.type)">{{ getTypeLabel(row.type) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="description" label="描述" show-overflow-tooltip />
      <el-table-column prop="source" label="来源" />
      <el-table-column prop="severity" label="严重程度">
        <template #default="{ row }">
          <el-tag :type="getSeverityTag(row.severity)">{{ row.severity }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="is_active" label="状态" width="120">
        <template #default="scope">
          <el-switch
            v-model="scope.row.is_active"
            @change="handleStatusChange(scope.row,scope.row.is_active)"
            active-text="启用"  
            inactive-text="禁用"
          />
        </template>
      </el-table-column>
      <el-table-column label="操作" width="150">
        <template #default="{ row }">
          <el-button size="small" @click="showDetails(row)">详情</el-button>
          <el-button size="small" type="danger" @click="deleteIntel(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 添加情报对话框 -->
    <el-dialog v-model="dialogVisible" title="添加威胁情报" width="50%">
      <el-form ref="formRef" :model="form" label-width="100px">
        <el-form-item label="情报类型" prop="type">
          <el-select 
            v-model="form.type"
            placeholder="请选择情报类型"
            clearable
            @change="handleTypeChange"
          >
            <el-option
              v-for="(label, value) in typeOptions"
              :key="value"
              :label="label"
              :value="value"
            />
          </el-select>
        </el-form-item>
        
        <el-form-item label="名称">
          <el-input v-model="form.name" />
        </el-form-item>
        
        <template v-if="form.type">
          <el-form-item label="描述">
            <el-input type="textarea" v-model="form.description" />
          </el-form-item>

          <el-form-item label="来源">
            <el-input v-model="form.source" />
          </el-form-item>
        </template>

        <el-form-item label="可信度">
          <el-slider v-model="form.confidence" :step="0.1" :min="0" :max="1" />
        </el-form-item>
        
        <el-form-item label="严重程度">
          <el-select v-model="form.severity">
            <el-option label="高" value="high" />
            <el-option label="中" value="medium" />
            <el-option label="低" value="low" />
          </el-select>
        </el-form-item>

        <el-form-item label="是否启用">
          <el-switch v-model="form.is_active" />
        </el-form-item>
        
        <!-- 通用特征匹配字段 -->
        <el-form-item label="特征内容">
          <el-input type="textarea" v-model="form.pattern_content" placeholder="请输入特征内容" />
        </el-form-item>
        
        <el-form-item label="匹配位置">
          <el-select v-model="form.match_location" placeholder="请选择匹配位置">
            <el-option label="URL" value="url" />
            <el-option label="请求-header" value="request_header" />
            <el-option label="响应-header" value="response_header" />
            <el-option label="Cookie" value="cookie" />
            <el-option label="请求-payload" value="request_payload" />
            <el-option label="响应-payload" value="response_payload" />
            <el-option label="任意" value="all" />
          </el-select>
        </el-form-item>
        
        <el-form-item label="是否正则">
          <el-switch v-model="form.is_regex" />
        </el-form-item>
        
        <el-form-item label="标签">
          <el-input v-model="form.tags" placeholder="请输入标签，多个标签用逗号分隔" />
        </el-form-item>
        
        <el-form-item label="参考信息">
          <el-input type="textarea" v-model="form.reference" placeholder="请输入参考信息" />
        </el-form-item>
        
        <!-- TOP10漏洞特有字段 -->
        <template v-if="form.type === 'top10'">
          <el-form-item label="漏洞类型">
            <el-select v-model="form.vulnerability_type" placeholder="请选择漏洞类型">
              <el-option label="注入漏洞" value="injection" />
              <el-option label="失效的身份认证" value="broken_auth" />
              <el-option label="敏感数据泄露" value="sensitive_data" />
              <el-option label="XML外部实体" value="xxe" />
              <el-option label="失效的访问控制" value="broken_access" />
              <el-option label="安全配置错误" value="security_misconfig" />
              <el-option label="跨站脚本" value="xss" />
              <el-option label="不安全的反序列化" value="insecure_deserialization" />
              <el-option label="使用含有已知漏洞的组件" value="vulnerable_components" />
              <el-option label="不足的日志记录和监控" value="insufficient_logging" />
            </el-select>
          </el-form-item>
          <el-form-item label="CWE编号">
            <el-input v-model="form.cwe_id" placeholder="如CWE-79" />
          </el-form-item>
          <el-form-item label="受影响系统">
            <el-input type="textarea" v-model="form.affected_systems" placeholder="请输入受影响的系统" />
          </el-form-item>
          <el-form-item label="缓解措施">
            <el-input type="textarea" v-model="form.mitigation" placeholder="请输入缓解措施" />
          </el-form-item>
        </template>
        
        <!-- Webshell攻击特有字段 -->
        <template v-if="form.type === 'webshell'">
          <el-form-item label="Webshell类型">
            <el-select v-model="form.shell_type" placeholder="请选择Webshell类型">
              <el-option label="一句话木马" value="one_liner" />
              <el-option label="大马" value="full_shell" />
              <el-option label="内存马" value="memory_shell" />
              <el-option label="加密型" value="encrypted" />
              <el-option label="变形免杀" value="obfuscated" />
            </el-select>
          </el-form-item>
          <el-form-item label="脚本语言">
            <el-select v-model="form.language" placeholder="请选择脚本语言">
              <el-option label="PHP" value="php" />
              <el-option label="JSP" value="jsp" />
              <el-option label="ASP" value="asp" />
              <el-option label="ASPX" value="aspx" />
              <el-option label="Python" value="python" />
            </el-select>
          </el-form-item>
          <el-form-item label="文件扩展名">
            <el-input v-model="form.file_extension" placeholder="如.php" />
          </el-form-item>
          <el-form-item label="检测方法">
            <el-select v-model="form.detection_method" placeholder="请选择检测方法">
              <el-option label="特征匹配" value="signature" />
              <el-option label="行为分析" value="behavior" />
              <el-option label="启发式检测" value="heuristic" />
              <el-option label="机器学习" value="ml" />
            </el-select>
          </el-form-item>
        </template>
        
        <!-- 木马特有字段 -->
        <template v-if="form.type === 'malware'">
          <el-form-item label="木马类型">
            <el-select v-model="form.malware_type" placeholder="请选择木马类型">
              <el-option label="远控木马" value="rat" />
              <el-option label="勒索软件" value="ransomware" />
              <el-option label="键盘记录" value="keylogger" />
              <el-option label="后门程序" value="backdoor" />
              <el-option label="蠕虫" value="worm" />
              <el-option label="僵尸网络" value="botnet" />
              <el-option label="挖矿木马" value="miner" />
            </el-select>
          </el-form-item>
          <el-form-item label="文件哈希">
            <el-input v-model="form.file_hash" placeholder="请输入文件哈希值" />
          </el-form-item>
          <el-form-item label="文件类型">
            <el-input v-model="form.file_type" placeholder="如EXE、DLL等" />
          </el-form-item>
          <el-form-item label="行为特征">
            <el-input type="textarea" v-model="form.behavior" placeholder="请描述木马的行为特征" />
          </el-form-item>
        </template>
        
        <!-- CVE特有字段 -->
        <template v-if="form.type === 'cve'">
          <el-form-item label="CVE编号">
            <el-input v-model="form.cve_id" placeholder="如CVE-2021-44228" />
          </el-form-item>
          <el-form-item label="CVSS评分">
            <el-input-number v-model="form.cvss_score" :min="0" :max="10" :step="0.1" />
          </el-form-item>
          <el-form-item label="受影响产品">
            <el-input type="textarea" v-model="form.affected_products" placeholder="请输入受影响的产品" />
          </el-form-item>
          <el-form-item label="补丁信息">
            <el-input type="textarea" v-model="form.patch_info" placeholder="请输入补丁信息" />
          </el-form-item>
        </template>
        
        <!-- POC特有字段 -->
        <template v-if="form.type === 'poc'">
          <el-form-item label="POC内容">
            <el-input type="textarea" v-model="form.poc_content" placeholder="请输入POC内容" />
          </el-form-item>
          <el-form-item label="目标类型">
            <el-input v-model="form.target_system" placeholder="请输入目标类型" />
          </el-form-item>
          <el-form-item label="利用方法">
            <el-input type="textarea" v-model="form.exploit_method" placeholder="请描述利用方法" />
          </el-form-item>
          <el-form-item label="相关CVE">
            <el-input v-model="form.related_cve" placeholder="请输入相关CVE编号" />
          </el-form-item>
        </template>
        
        <!-- 恶意IP特有字段 -->
        <template v-if="form.type === 'ip'">
          <el-form-item label="IP地址">
            <el-input v-model="form.ip_address" placeholder="请输入IP地址" />
          </el-form-item>
          <el-form-item label="IP类型">
            <el-select v-model="form.ip_type" placeholder="请选择IP类型">
              <el-option label="C2服务器" value="c2" />
              <el-option label="扫描器" value="scanner" />
              <el-option label="爬虫" value="crawler" />
              <el-option label="攻击源" value="attacker" />
              <el-option label="代理" value="proxy" />
              <el-option label="僵尸网络" value="botnet" />
            </el-select>
          </el-form-item>
         
        </template>
        
        <!-- C2服务器特有字段 -->
        <template v-if="form.type === 'c2'">
          <el-form-item label="IP地址">
            <el-input v-model="form.ip_address" placeholder="请输入IP地址" />
          </el-form-item>
          <el-form-item label="域名">
            <el-input v-model="form.domain" placeholder="请输入域名" />
          </el-form-item>
          <el-form-item label="C2类型">
            <el-input v-model="form.c2_type" placeholder="请输入C2类型" />
          </el-form-item>
          <el-form-item label="恶意软件家族">
            <el-input v-model="form.malware_family" placeholder="请输入恶意软件家族" />
          </el-form-item>
          <el-form-item label="通信协议">
            <el-select v-model="form.protocol" placeholder="请选择通信协议">
              <el-option label="HTTP" value="http" />
              <el-option label="HTTPS" value="https" />
              <el-option label="TCP" value="tcp" />
              <el-option label="UDP" value="udp" />
              <el-option label="DNS" value="dns" />
              <el-option label="ICMP" value="icmp" />
            </el-select>
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number v-model="form.port" :min="1" :max="65535" />
          </el-form-item>
        </template>
        
        <!-- 敏感信息特有字段 -->
        <template v-if="form.type === 'sensitive'">
          <el-form-item label="信息类型">
            <el-select v-model="form.info_type" placeholder="请选择信息类型">
              <el-option label="个人身份信息" value="pii" />
              <el-option label="支付卡信息" value="payment" />
              <el-option label="健康医疗信息" value="health" />
              <el-option label="凭证信息" value="credentials" />
              <el-option label="API密钥" value="api_key" />
              <el-option label="内部文档" value="internal_doc" />
              <el-option label="源代码" value="source_code" />
            </el-select>
          </el-form-item>
   
        
          <el-form-item label="操作类型">
            <el-select v-model="form.operation_type" placeholder="请选择操作类型">
              <el-option label="泄露" value="leak" />
              <el-option label="窃取" value="theft" />
              <el-option label="篡改" value="tamper" />
              <el-option label="删除" value="delete" />
              <el-option label="未授权访问" value="unauthorized_access" />
            </el-select>
          </el-form-item>
        </template>

        <!--恶意工具-->
        <template v-if="form.type === 'tool'">
          <el-form-item label="工具名称">
            <el-input v-model="form.tool_name" placeholder="请输入工具名称" />
          </el-form-item>
          <el-form-item label="工具类型">
            <el-select v-model="form.tool_type" placeholder="请选择工具类型">
              <el-option label="漏扫" value="scan" />
              <el-option label="黑客工具" value="malicious_scan" />
            </el-select>
          </el-form-item>
          
        </template>
      </el-form>
      
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="submitForm">确定</el-button>
      </template>
    </el-dialog>

    <!-- 详情对话框 -->
    <el-dialog v-model="detailsVisible" title="情报详情" width="50%">
      <div v-if="currentIntel">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="类型">{{ getTypeLabel(currentIntel.type) }}</el-descriptions-item>
          <el-descriptions-item label="名称">{{ currentIntel.name }}</el-descriptions-item>
          <el-descriptions-item label="描述">{{ currentIntel.description }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ currentIntel.source }}</el-descriptions-item>
          <el-descriptions-item label="可信度">{{ currentIntel.confidence }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">{{ currentIntel.severity }}</el-descriptions-item>
          <el-descriptions-item label="是否启用">{{ currentIntel.is_active ? '是' : '否' }}</el-descriptions-item>
          
          <!-- 通用特征匹配字段 -->
          <el-descriptions-item label="特征内容">{{ currentIntel.pattern_content }}</el-descriptions-item>
          <el-descriptions-item label="匹配位置">{{ currentIntel.match_location }}</el-descriptions-item>
          <el-descriptions-item label="是否正则">{{ currentIntel.is_regex ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="标签">{{ currentIntel.tags }}</el-descriptions-item>
          <el-descriptions-item label="参考信息">{{ currentIntel.reference }}</el-descriptions-item>
          
          <!-- TOP10漏洞特有字段 -->
          <template v-if="currentIntel.type === 'top10'">
            <el-descriptions-item label="漏洞类型">{{ currentIntel.vulnerability_type }}</el-descriptions-item>
            <el-descriptions-item label="CWE编号">{{ currentIntel.cwe_id }}</el-descriptions-item>
            <el-descriptions-item label="受影响系统">{{ currentIntel.affected_systems }}</el-descriptions-item>
            <el-descriptions-item label="缓解措施">{{ currentIntel.mitigation }}</el-descriptions-item>
          </template>
          
          <!-- Webshell攻击特有字段 -->
          <template v-if="currentIntel.type === 'webshell'">
            <el-descriptions-item label="Webshell类型">{{ currentIntel.shell_type }}</el-descriptions-item>
            <el-descriptions-item label="脚本语言">{{ currentIntel.language }}</el-descriptions-item>
            <el-descriptions-item label="文件扩展名">{{ currentIntel.file_extension }}</el-descriptions-item>
            <el-descriptions-item label="检测方法">{{ currentIntel.detection_method }}</el-descriptions-item>
          </template>
          
          <!-- 木马特有字段 -->
          <template v-if="currentIntel.type === 'malware'">
            <el-descriptions-item label="木马类型">{{ currentIntel.malware_type }}</el-descriptions-item>
            <el-descriptions-item label="文件哈希">{{ currentIntel.file_hash }}</el-descriptions-item>
            <el-descriptions-item label="文件类型">{{ currentIntel.file_type }}</el-descriptions-item>
            <el-descriptions-item label="行为特征">{{ currentIntel.behavior }}</el-descriptions-item>
          </template>
          
          <!-- CVE类型特有字段 -->
          <template v-if="currentIntel.type === 'cve'">
            <el-descriptions-item label="CVE编号">{{ currentIntel.cve_id }}</el-descriptions-item>
            <el-descriptions-item label="CVSS评分">{{ currentIntel.cvss_score }}</el-descriptions-item>
            <el-descriptions-item label="受影响产品">{{ currentIntel.affected_products }}</el-descriptions-item>
            <el-descriptions-item label="补丁信息">{{ currentIntel.patch_info }}</el-descriptions-item>
          </template>
          
          <!-- POC类型特有字段 -->
          <template v-if="currentIntel.type === 'poc'">
            <el-descriptions-item label="POC内容">{{ currentIntel.poc_content }}</el-descriptions-item>
            <el-descriptions-item label="目标系统">{{ currentIntel.target_system }}</el-descriptions-item>
            <el-descriptions-item label="利用方法">{{ currentIntel.exploit_method }}</el-descriptions-item>
            <el-descriptions-item label="相关CVE">{{ currentIntel.related_cve }}</el-descriptions-item>
          </template>
          
          <!-- 恶意IP类型特有字段 -->
          <template v-if="currentIntel.type === 'ip'">
            <el-descriptions-item label="IP地址">{{ currentIntel.ip_address }}</el-descriptions-item>
            <el-descriptions-item label="IP类型">{{ currentIntel.ip_type }}</el-descriptions-item>
          </template>
          
          <!-- C2服务器特有字段 -->
          <template v-if="currentIntel.type === 'c2'">
            <el-descriptions-item label="IP地址">{{ currentIntel.ip_address }}</el-descriptions-item>
            <el-descriptions-item label="域名">{{ currentIntel.domain }}</el-descriptions-item>
            <el-descriptions-item label="C2类型">{{ currentIntel.c2_type }}</el-descriptions-item>
            <el-descriptions-item label="恶意软件家族">{{ currentIntel.malware_family }}</el-descriptions-item>
            <el-descriptions-item label="通信协议">{{ currentIntel.protocol }}</el-descriptions-item>
            <el-descriptions-item label="端口">{{ currentIntel.port }}</el-descriptions-item>
          </template>
          
          <!-- 敏感信息特有字段 -->
          <template v-if="currentIntel.type === 'sensitive'">
            <el-descriptions-item label="信息类型">{{ currentIntel.info_type }}</el-descriptions-item>
            <el-descriptions-item label="操作类型">{{ currentIntel.operation_type }}</el-descriptions-item>
          </template>
          
          <el-descriptions-item label="更新时间">{{ currentIntel.update_time }}</el-descriptions-item>
        </el-descriptions>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import axios from 'axios'

export default {
  name: 'ThreatIntelligence',
  components: {
    Plus
  },
  setup() {
    // 威胁情报列表
    const threatIntelList = ref([])
    
    // 类型选项
    const typeOptions = {
      'top10': 'TOP10漏洞',
      'webshell': 'Webshell攻击',
      'malware': '木马',
      'cve': 'CVE',
      'poc': 'POC',
      'ip': '恶意IP',
      'c2': 'C2服务信息',
      'sensitive': '敏感信息泄露',
      'tool': '恶意工具'
    }
    
    // 对话框可见性
    const dialogVisible = ref(false)
    const detailsVisible = ref(false)
    
    // 当前查看的情报
    const currentIntel = ref(null)
    
    // 筛选条件
    const filterCategory = ref('')
    const filterType = ref('')
    
    // 表单数据
    const form = reactive({
      type: '',
      name: '',
      description: '',
      source: '',
      confidence: 0.5,
      severity: 'medium',
      is_active: true,
      // 类别ID
      category_id: null,
      // 通用特征字段
      pattern_content: '',
      match_location: '',
      is_regex: false,
      tags: '',
      reference: '',
      
      // TOP10漏洞特有字段
      vulnerability_type: '',
      cwe_id: '',
      affected_systems: '',
      mitigation: '',
      
      // Webshell攻击特有字段
      shell_type: '',
      language: '',
      file_extension: '',
      detection_method: '',
      
      // 木马特有字段
      malware_type: '',
      file_hash: '',
      file_type: '',
      behavior: '',
      
      // CVE特有字段
      cve_id: '',
      cvss_score: 0,
      affected_products: '',
      patch_info: '',
      
      // POC特有字段
      poc_content: '',
      target_system: '',
      exploit_method: '',
      
      // 恶意IP特有字段
      ip_address: '',
      ip_type: '',
   
      
      // C2服务器特有字段
      c2_type: '',
      malware_family: '',
      port: '',
      protocol: '',
      
      // 敏感信息特有字段
      info_type: '',
      data_format: '',
      detection_pattern: '',

      // 恶意工具特有字段
      tool_name: '',
      tool_type: ''
    })
    
    // 表单引用
    const formRef = ref(null)
    
    // 类别列表
    const categories = ref([])
    
    // 获取威胁情报列表
    const fetchThreatIntelList = async () => {
      try {
        // 构建查询参数
        const params = {}
        if (filterCategory.value) {
          params.category_id = filterCategory.value
        }
        if (filterType.value) {
          params.type = filterType.value
        }
        
        const response = await axios.get('http://localhost:5000/api/threat-intel', { params })
        if (response.data.success) {
          threatIntelList.value = response.data.data
          // 为每个情报项添加类型标识
          threatIntelList.value.forEach(item => {
            // 根据特有字段判断类型
            if (item.vulnerability_type) item.type = 'top10'
            else if (item.shell_type) item.type = 'webshell'
            else if (item.malware_type) item.type = 'malware'
            else if (item.cve_id) item.type = 'cve'
            else if (item.poc_content) item.type = 'poc'
            else if (item.ip_address && item.ip_type) item.type = 'ip'
            else if ((item.ip_address || item.domain)) item.type = 'c2'
            else if (item.info_type) item.type = 'sensitive'
            else if (item.tool_name) item.type = 'tool'
            else item.type = 'pattern' // 默认为基本特征类型
          })
        } else {
          ElMessage.error(response.data.message || '获取威胁情报失败')
        }
      } catch (error) {
        console.error('获取威胁情报失败:', error)
        ElMessage.error('获取威胁情报失败')
      }
    }
    
    // 加载威胁情报列表（支持筛选）
    const loadThreatIntelList = () => {
      fetchThreatIntelList()
    }
    
    // 获取威胁情报类别
    const fetchCategories = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/threat-intel/categories')
        if (response.data.success) {
          categories.value = response.data.data
        } else {
          ElMessage.error(response.data.message || '获取威胁情报类别失败')
        }
      } catch (error) {
        console.error('获取威胁情报类别失败:', error)
        ElMessage.error('获取威胁情报类别失败')
      }
    }
    
    // 根据类型获取标签类型
    const getTypeTag = (type) => {
      const tagMap = {
        'top10': 'danger',
        'webshell': 'warning',
        'malware': 'danger',
        'cve': 'warning',
        'poc': 'warning',
        'ip': 'info',
        'c2': 'danger',
        'sensitive': 'info',
        'pattern': 'success'
      }
      return tagMap[type] || 'info'
    }
    
    // 根据类型获取标签文本
    const getTypeLabel = (type) => {
      return typeOptions[type] || '未知类型'
    }
    
    // 根据严重程度获取标签类型
    const getSeverityTag = (severity) => {
      const tagMap = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info'
      }
      return tagMap[severity] || 'info'
    }
    
    // 处理类型变更
    const handleTypeChange = () => {
      // 重置特有字段
      form.vulnerability_type = ''
      form.cwe_id = ''
      form.affected_systems = ''
      form.mitigation = ''
      form.shell_type = ''
      form.language = ''
      form.file_extension = ''
      form.detection_method = ''
      form.malware_type = ''
      form.file_hash = ''
      form.file_type = ''
      form.behavior = ''
      form.cve_id = ''
      form.cvss_score = 0
      form.affected_products = ''
      form.patch_info = ''
      form.poc_content = ''
      form.target_system = ''
      form.exploit_method = ''
      form.ip_address = ''
      form.domain = ''
      form.port = ''
      form.protocol = ''
      form.info_type = ''
      form.data_format = ''
      form.detection_pattern = ''
      form.tool_name = ''
      form.tool_type = ''
    }
    
    // 提交表单
    const submitForm = async () => {
      if (!form.type) {
        ElMessage.warning('请选择情报类型')
        return
      }
      
      if (!form.name) {
        ElMessage.warning('请输入情报名称')
        return
      }
      
      try {
        // 如果没有选择类别，创建一个默认类别
        if (!form.category_id) {
          // 查找或创建对应类型的类别
          const categoryName = typeOptions[form.type]
          let category = categories.value.find(c => c.name === categoryName)
          
          if (!category) {
            try {
              // 创建新类别
              const categoryResponse = await axios.post('http://localhost:5000/api/threat-intel/categories', {
                name: categoryName,
                code: form.type.toUpperCase(),
                description: `${categoryName}类型的威胁情报`
              })
              
              if (categoryResponse.data.success) {
                category = categoryResponse.data.data
                categories.value.push(category)
              }
            } catch (error) {
              // 如果是因为重复名称导致的错误，尝试获取已存在的类别
              if (error.response && error.response.status === 409) {
                const existingCategoryResponse = await axios.get('http://localhost:5000/api/threat-intel/categories')
                if (existingCategoryResponse.data.success) {
                  category = existingCategoryResponse.data.data.find(c => c.name === categoryName)
                  if (category) {
                    categories.value = existingCategoryResponse.data.data
                  }
                }
              } else {
                throw error
              }
            }
          }
          
          if (!category) {
            ElMessage.error('无法创建或获取类别')
            return
          }
          
          form.category_id = category.id
        }
        
        // 提交情报数据
        const response = await axios.post('http://localhost:5000/api/threat-intel', {
          ...form
        })
        
        if (response.data.success) {
          ElMessage.success('添加情报成功')
          dialogVisible.value = false
          
          // 重置表单
          form.type = ''
          form.name = ''
          form.description = ''
          form.source = ''
          form.confidence = 0.5
          form.severity = 'medium'
          form.is_active = true
          form.category_id = null
          form.pattern_content = ''
          form.match_location = ''
          form.is_regex = false
          form.tags = ''
          form.reference = ''
          handleTypeChange() // 重置特有字段

          // 重新获取列表数据
          await fetchThreatIntelList()
        } else {
          ElMessage.error(response.data.message || '添加情报失败')
        }
      } catch (error) {
        console.error('添加情报失败:', error)
        ElMessage.error('添加情报失败')
      }
    }
    
    // 显示详情
    const showDetails = (row) => {
      currentIntel.value = row
      detailsVisible.value = true
    }
    
    // 删除情报
    const deleteIntel = (row) => {
      ElMessageBox.confirm('确定要删除该情报吗？', '提示', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }).then(async () => {
        try {
          const response = await axios.delete(`http://localhost:5000/api/threat-intel/${row.id}`)
          if (response.data.success) {
            ElMessage.success('删除成功')
            fetchThreatIntelList()
          } else {
            ElMessage.error(response.data.message || '删除失败')
          }
        } catch (error) {
          console.error('删除情报失败:', error)
          ElMessage.error('删除失败')
        }
      }).catch(() => {})
    }
    
    // 修改状态
    const handleStatusChange = async (row, status) => {
      try {
        const response = await axios.put(`http://localhost:5000/api/threat-intel/${row.id}`, {
          type: row.type,
          is_active: status
        })
        
        if (response.data.success) {
          ElMessage.success(`${status ? '启用' : '禁用'}成功`)
        } else {
          // 恢复原状态
          row.is_active = !status
          ElMessage.error(response.data.message || `${status ? '启用' : '禁用'}失败`)
        }
      } catch (error) {
        // 恢复原状态
        row.is_active = !status
        console.error(`${status ? '启用' : '禁用'}情报失败:`, error)
        ElMessage.error(`${status ? '启用' : '禁用'}失败`)
      }
    }
    
    onMounted(() => {
      fetchThreatIntelList()
      fetchCategories()
    })
    
    return {
      threatIntelList,
      typeOptions,
      dialogVisible,
      detailsVisible,
      currentIntel,
      form,
      formRef,
      categories,
      filterCategory,
      filterType,
      getTypeTag,
      getTypeLabel,
      getSeverityTag,
      handleTypeChange,
      submitForm,
      showDetails,
      deleteIntel,
      handleStatusChange,
      loadThreatIntelList
    }
  }
}
</script>

<style scoped>
.threat-intel-container {
  padding: 20px;
}

.operation-bar {
  display: flex;
  justify-content: space-between;
  margin-bottom: 20px;
}
</style>