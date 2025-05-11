<template>
  
  <div class="traffic-analyzer">
    <el-dialog
      v-model="showAdvancedFilter"
      title="高级筛选"
      width="500px"
    >
      <el-form :model="filterForm" label-width="100px">
        <el-form-item label="源IP">
          <el-input v-model="filterForm.sourceIp" placeholder="请输入源IP"></el-input>
        </el-form-item>
        <el-form-item label="目的IP">
          <el-input v-model="filterForm.destIp" placeholder="请输入目的IP"></el-input>
        </el-form-item>
        <el-form-item label="流量类型">
          <el-select v-model="filterForm.trafficType" placeholder="请选择流量类型">
            <el-option label="全部" value=""></el-option>
            <el-option label="TOP10漏洞" value="top10"></el-option>
            <el-option label="Webshell攻击" value="webshell"></el-option>
            <el-option label="木马" value="malware"></el-option>
            <el-option label="CVE" value="cve"></el-option>
            <el-option label="POC" value="poc"></el-option>
            <el-option label="恶意IP" value="ip"></el-option>
            <el-option label="C2服务信息" value="c2"></el-option>
            <el-option label="敏感信息泄露" value="sensitive"></el-option>
            <el-option label="正常流量" value="normal"></el-option>
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="showAdvancedFilter = false">取消</el-button>
          <el-button type="primary" @click="applyFilter">确定</el-button>
        </span>
      </template>
    </el-dialog>
    <div class="stats-cards">
      <div class="stat-card">
        <h3>总流量</h3>
        <div class="number">{{ stats.total }}</div>
      </div>
      <div class="stat-card">
        <h3>可疑流量</h3>
        <div class="number warning">{{ stats.suspicious }}</div>
        <div class="trend">需要关注</div>
      </div>
      <div class="stat-card">
        <h3>恶意流量</h3>
        <div class="number danger">{{ stats.malicious }}</div>
        <div class="trend">立即处理</div>
      </div>
    </div>

    <div class="filter-section">
      <el-date-picker
        v-model="selectedDateRange"
        type="daterange"
        range-separator="至"
        start-placeholder="开始日期"
        end-placeholder="结束日期"
        :picker-options="pickerOptions"
        @change="handleDateRangeChange"
      />
      <el-select v-model="timeRange" placeholder="时间范围" @change="fetchTrafficData">
        <el-option label="最近1小时" value="1h" />
        <el-option label="最近24小时" value="24h" />
        <el-option label="最近7天" value="7d" />
      </el-select>
      <el-select v-model="selectedProtocol" placeholder="协议" @change="fetchTrafficData">
        <el-option label="全部" value="" />
        <el-option label="TCP" value="TCP" />
        <el-option label="UDP" value="UDP" />
        <el-option label="ICMP" value="ICMP" />
        <el-option label="HTTP" value="HTTP" />
        <el-option label="HTTPS" value="HTTPS" />
      </el-select>
      <el-select v-model="selectedRiskLevel" placeholder="风险等级" @change="fetchTrafficData">
        <el-option label="全部" value="" />
        <el-option label="低风险" value="low" />
        <el-option label="中风险" value="medium" />
        <el-option label="高风险" value="high" />
      </el-select>
    </div>

    <div class="charts-container">
      <div class="chart-card">
        <h3>流量趋势</h3>
        <div class="chart" ref="trendChart"></div>
      </div>
      <div class="chart-card">
        <h3>流量告警类型分布</h3>
        <div class="chart" ref="protocolChart"></div>
      </div>
    </div>

    <div class="traffic-table">
      <div class="table-header">
      <h3>实时流量</h3>
        <el-button type="primary" @click="exportData" :loading="exporting">
          导出Excel
        </el-button>
      </div>
      <div class="table-container">
        
        <el-table 
          :data="currentPageData" 
          style="width: 100%" 
          v-loading="loading"
          :empty-text="'暂无数据'"
          border
        >
          <el-table-column prop="timestamp" label="时间" min-width="180">
            <template #default="scope">
              <template v-if="scope && scope.row">
                {{ formatTime(scope.row.timestamp) }}
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="source_ip" label="源IP" min-width="180">
            <template #default="scope">
              <template v-if="scope && scope.row">
                {{ scope.row.source_ip }}:{{ scope.row.source_port }}
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="destination_ip" label="目标IP" min-width="180">
            <template #default="scope">
              <template v-if="scope && scope.row">
                {{ scope.row.destination_ip }}:{{ scope.row.destination_port }}
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="protocol" label="协议" width="100">
            <template #default="scope">
              <template v-if="scope && scope.row">
                {{ scope.row.protocol }}
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="packet_size" label="大小" width="120">
            <template #default="scope">
              <template v-if="scope && scope.row">
                {{ formatSize(scope.row.packet_size) }}
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="traffic_type" label="流量类型" width="120">
            <template #default="scope">
              <el-tag
                :type="getTrafficTypeStyle(scope.row.traffic_type)"
                effect="light"
              >
                {{ getTrafficTypeLabel(scope.row.traffic_type) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="risk_level" label="风险等级" width="120">
            <template #default="scope">
              <template v-if="scope && scope.row">
                <span :class="['risk-tag', scope.row.risk_level]">
                  {{ formatRiskLevel(scope.row.risk_level) }}
                </span>
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="status" label="数据包类型" width="120">
            <template #default="scope">
              <template v-if="scope && scope.row">
                <span :class="['status-tag', scope.row.packet_type]">
                  {{formatPacketType(scope.row.packet_type) }}
                </span>
              </template>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="scope">
              <template v-if="scope && scope.row">
                <el-button 
                  type="primary" 
                  size="small" 
                  @click="showDetail(scope.row)"
                >
                  详情
                </el-button>
              </template>
            </template>
          </el-table-column>
         
        </el-table>
        <div class="pagination-container">
          <el-pagination
            :current-page="currentPage"
            :page-size="pageSize"
            :page-sizes="[20, 50, 100]"
            :total="total"
            layout="total, sizes, prev, pager, next"
            @size-change="handleSizeChange"
            @current-change="handleCurrentChange"
            @update:current-page="currentPage = $event"
            @update:page-size="pageSize = $event"
          />
        </div>
      </div>
    </div>

    <!-- 详情弹窗 -->
    <el-drawer
      v-model="detailVisible"
      title="流量详情"
      direction="rtl"
      size="50%"
      :before-close="handleClose"
    >
      <div v-if="currentDetail" class="detail-content">
        <div class="detail-row">
          <span class="label">时间：</span>
          <span>{{ formatTime(currentDetail.timestamp) }}</span>
        </div>
        <div class="detail-row">
          <span class="label">源IP：</span>
          <span>{{ currentDetail.source_ip }}:{{ currentDetail.source_port }}</span>
        </div>
        <div class="detail-row">
          <span class="label">目标IP：</span>
          <span>{{ currentDetail.destination_ip }}:{{ currentDetail.destination_port }}</span>
        </div>
        <div class="detail-row">
          <span class="label">协议：</span>
          <span>{{ currentDetail.protocol }}</span>
        </div>
        <div class="detail-row">
          <span class="label">数据包大小：</span>
          <span>{{ formatSize(currentDetail.packet_size) }}</span>
        </div>
        <div class="detail-row">
          <span class="label">风险等级：</span>
          <span :class="['risk-tag', currentDetail.risk_level]">
            {{ formatRiskLevel(currentDetail.risk_level) }}
          </span>
        </div>
        <div class="detail-row">
          <span class="label">威胁类型：</span>
          <pre class="threat-type">{{formatThreatType(currentDetail.threat_type)}}</pre>
        </div>
        <div class="detail-row">
          <span class="label">状态码：</span>
          <span :class="['status-tag', currentDetail.response_code]">
            <span style="font-size:large;">{{currentDetail.response_code}}</span>
          </span>
        </div>
        <div class="detail-row">
          <span class="label">Header体：</span>
          <pre>{{ formatHeader(currentDetail.header_body) }}</pre>
        </div>
        <div class="detail-row payload">
          <span class="label">Payload：</span>
          <pre>{{ formatPayload(currentDetail.payload) }}</pre>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue';
import * as echarts from 'echarts';
import axios from 'axios';
import io from 'socket.io-client';
import { ElMessage } from 'element-plus';
import * as XLSX from 'xlsx'

export default {
  name: 'TrafficAnalyzer',
  setup() {
    const showAdvancedFilter = ref(false);
    const filterForm = ref({
      sourceIp: '',
      destIp: '',
      trafficType: ''
    });
    const applyFilter = () => {
      currentPage.value = 1; // 重置到第一页
      fetchTrafficData();
      showAdvancedFilter.value = false;
    };
    const selectedDateRange = ref(null);
    const timeRange = ref('1h');
    const selectedProtocol = ref('');
    const selectedRiskLevel = ref('');
    const trafficData = ref([]);
    const stats = ref({
      total: 0,
      suspicious: 0,
      malicious: 0
    });
    const trendChart = ref(null);
    const protocolChart = ref(null);
    let trendChartInstance = null;
    let protocolChartInstance = null;
    let socket = null;
    const detailVisible = ref(false);
    const currentDetail = ref(null);
    const pickerOptions = ref({
      shortcuts: [{
        text: '最近一周',
        onClick(picker) {
          const end = new Date();
          const start = new Date();
          start.setTime(start.getTime() - 3600 * 1000 * 24 * 7);
          picker.$emit('pick', [start, end]);
        }
      }, {
        text: '最近一个月',
        onClick(picker) {
          const end = new Date();
          const start = new Date();
          start.setTime(start.getTime() - 3600 * 1000 * 24 * 30);
          picker.$emit('pick', [start, end]);
        }
      }, {
        text: '最近三个月',
        onClick(picker) {
          const end = new Date();
          const start = new Date();
          start.setTime(start.getTime() - 3600 * 1000 * 24 * 90);
          picker.$emit('pick', [start, end]);
        }
      }]
    });
    const currentPage = ref(1);
    const pageSize = ref(20);
    const total = ref(0);
    const loading = ref(false);
    const exporting = ref(false);
    
    // 添加流量类型标签映射
    const trafficTypeLabels = {
      'top10': 'TOP10漏洞',
      'webshell': 'Webshell攻击',
      'malware': '木马',
      'cve': 'CVE',
      'poc': 'POC',
      'ip': '恶意IP',
      'c2': 'C2服务信息',
      'sensitive': '敏感信息泄露',
      'port_scan': '端口/恶意工具扫描',
      'nmap_scan': 'Nmap扫描',
      'normal': '正常流量',
      'unknown': '未知类型',
      'tool': '黑客工具'
    };

    // 添加流量类型样式映射
    const getTrafficTypeStyle = (type) => {
      const styles = {
        'top10': 'danger',
        'webshell': 'danger',
        'malware': 'danger',
        'cve': 'warning',
        'poc': 'warning',
        'ip': 'warning',
        'c2': 'danger',
        'sensitive': 'info',
        'port_scan': 'warning',
        'nmap_scan': 'warning',
        'normal': 'success',
        'unknown': 'info',
        'tool': 'warning'
      };
      return styles[type] || 'info';
    };

    // 获取流量类型显示标签
    const getTrafficTypeLabel = (type) => {
      return trafficTypeLabels[type] || '未知类型';
    };

    const currentPageData = computed(() => {
      // 直接返回当前页的数据，因为后端已经处理了分页
      return trafficData.value;
    });

    const showDetail = (item) => {
      currentDetail.value = item;
      detailVisible.value = true;
    };

    const handleClose = () => {
      detailVisible.value = false;
      currentDetail.value = null;
    };

    const formatPayload = (payload) => {
      if (!payload) return '无数据';
      try {
        // 尝试解码base64
        const decoded = payload;
        // 尝试解析为JSON
        try {
          return JSON.stringify(JSON.parse(decoded), null, 2);
        } catch {
          return decoded;
        }
      } catch {
        return payload;
      }
    };

    const formatHeader = (header) => {
      if (!header) return '无';
      try {
        // 尝试解析JSON格式的header
        const headerObj = JSON.parse(header);
        return JSON.stringify(headerObj, null, 2);
      } catch {
        // 如果不是JSON格式，直接返回原始字符串
        return header;
      }
    };

    const formatTime = (timestamp) => {
      if (!timestamp) return '';
      try {
        const date = new Date(timestamp);
        return date.toLocaleString('zh-CN', {
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false
        });
      } catch (e) {
        console.error('Error formatting time:', e);
        return timestamp;
      }
    };

    const initSocket = () => {
      // 连接到WebSocket服务器
      socket = io('http://localhost:5000');

      // 监听连接事件
      socket.on('connect', () => {
        console.log('Connected to WebSocket server');
        // 请求初始统计数据
        socket.emit('request_traffic_stats');
      });

      // 监听流量更新事件
      socket.on('traffic_update', (data) => {
        // 更新统计数据
        stats.value = data.stats;
        
        // 更新流量数据（只保留最新的100条）
        trafficData.value = [
          ...data.recent,
          ...trafficData.value.slice(0, 100 - data.recent.length)
        ];
      });

      // 监听统计更新事件
      socket.on('traffic_stats', (data) => {
        updateCharts(data);
      });

      // 监听错误事件
      socket.on('error', (error) => {
        console.error('WebSocket error:', error);
      });
    };

    const fetchTrafficData = async () => {
      try {
        loading.value = true;
        const params = new URLSearchParams({
          limit: pageSize.value.toString(),
          offset: ((currentPage.value - 1) * pageSize.value).toString()
        });

        // 添加筛选参数
        if (filterForm.value.sourceIp) {
          params.append('source_ip', filterForm.value.sourceIp);
        }
        if (filterForm.value.destIp) {
          params.append('destination_ip', filterForm.value.destIp);
        }
        if (filterForm.value.trafficType) {
          params.append('traffic_type', filterForm.value.trafficType);
        }

        // 处理日期范围
        if (selectedDateRange.value && selectedDateRange.value.length === 2) {
          const formatDate = (date) => {
            const d = new Date(date);
            return d.toISOString();
          };
          params.append('start_time', formatDate(selectedDateRange.value[0]));
          params.append('end_time', formatDate(selectedDateRange.value[1]));
        } else if (timeRange.value) {
          // 处理时间范围
          const now = new Date();
          let startTime = new Date();
          
          switch (timeRange.value) {
            case '1h':
              startTime.setHours(now.getHours() - 1);
              break;
            case '24h':
              startTime.setDate(now.getDate() - 1);
              break;
            case '7d':
              startTime.setDate(now.getDate() - 7);
              break;
          }
          
          params.append('start_time', startTime.toISOString());
          params.append('end_time', now.toISOString());
        }
        
        // 添加协议筛选
        if (selectedProtocol.value) {
          params.append('protocol', selectedProtocol.value);
        }
        
        // 添加风险等级筛选
        if (selectedRiskLevel.value) {
          params.append('risk_level', selectedRiskLevel.value);
        }

        console.log('Fetching data with params:', params.toString());
        const response = await axios.get(`http://localhost:5000/api/traffic?${params.toString()}`);
        console.log('Received response:', response.data);

        if (response.data && Array.isArray(response.data.traffic)) {
          // 修改这里：直接使用返回的数据，不进行分页处理
          trafficData.value = response.data.traffic.map(item => ({
            ...item,
            timestamp: new Date(item.timestamp).toISOString()
          }));
          total.value = response.data.total || 0;
          
          // 更新统计数据
          stats.value = {
            total: response.data.total || 0,
            suspicious: response.data.suspicious || 0,
            malicious: response.data.malicious || 0
          };
          
          // 更新图表数据
          if (response.data.stats) {
            updateCharts(response.data.stats);
          }
        } else {
          console.warn('Invalid response format:', response.data);
          trafficData.value = [];
          total.value = 0;
          stats.value = {
            total: 0,
            suspicious: 0,
            malicious: 0
          };
        }
      } catch (error) {
        console.error('Error fetching traffic data:', error);
        ElMessage.error('获取流量数据失败');
        trafficData.value = [];
        total.value = 0;
      } finally {
        loading.value = false;
      }
    };

    const updateCharts = (data) => {
      // 更新趋势图
      trendChartInstance.setOption({
        tooltip: {
          trigger: 'axis'
        },
        xAxis: {
          type: 'category',
          data: data.hourly_stats.map(item => item.hour)
        },
        yAxis: {
          type: 'value',
          name: '流量数量'
        },
        series: [{
          data: data.hourly_stats.map(item => item.count),
          type: 'bar',
          barWidth: '60%',
          itemStyle: {
            color: '#409EFF'
          }
        }]
      });

      // 更新流量告警类型分布图
      const currentTrafficData = trafficData.value || [];
      
      // 统计各类型漏洞数量
      const threatCounts = {
        top10: 0,
        webshell: 0,
        malware: 0,
        cve: 0,
        poc: 0,
        ip: 0,
        c2: 0,
        sensitive: 0
      };

      // 遍历流量数据，统计各类型漏洞
      currentTrafficData.forEach(item => {
        if (item.threat_type) {
          try {
            const threats = typeof item.threat_type === 'string' 
              ? JSON.parse(item.threat_type.replace(/'/g, '"'))
              : item.threat_type;

            if (Array.isArray(threats)) {
              threats.forEach(threat => {
                if (threat.category && Object.prototype.hasOwnProperty.call(threatCounts, threat.category)) {
                  threatCounts[threat.category]++;
                }
              });
            }
          } catch (e) {
            console.error('解析威胁类型失败:', e);
          }
        }
      });

      // 构建饼图数据
      const riskData = [
        { 
          value: threatCounts.top10, 
          name: 'TOP10漏洞',
          itemStyle: { color: '#f5222d' }
        },
        { 
          value: threatCounts.webshell, 
          name: 'Webshell攻击',
          itemStyle: { color: '#fa8c16' }
        },
        { 
          value: threatCounts.malware, 
          name: '木马',
          itemStyle: { color: '#eb2f96' }
        },
        { 
          value: threatCounts.cve, 
          name: 'CVE漏洞',
          itemStyle: { color: '#faad14' }
        },
        { 
          value: threatCounts.poc, 
          name: 'POC攻击',
          itemStyle: { color: '#722ed1' }
        },
        { 
          value: threatCounts.ip, 
          name: '恶意IP',
          itemStyle: { color: '#13c2c2' }
        },
        { 
          value: threatCounts.c2, 
          name: 'C2服务信息',
          itemStyle: { color: '#eb2f96' }
        },
        { 
          value: threatCounts.sensitive, 
          name: '敏感信息泄露',
          itemStyle: { color: '#52c41a' }
        }
      ];

      // 计算正常流量数量
      const totalThreats = Object.values(threatCounts).reduce((sum, count) => sum + count, 0);
      const normalTraffic = data.total - totalThreats;
      riskData.push({ 
        value: normalTraffic > 0 ? normalTraffic : 0, 
        name: '正常流量',
        itemStyle: { color: '#1890ff' }
      });

      // 过滤掉数量为0的数据
      const filteredRiskData = riskData.filter(item => item.value > 0);

      protocolChartInstance.setOption({
        tooltip: {
          trigger: 'item',
          formatter: '{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'vertical',
          left: 'left',
          type: 'scroll',
          formatter: function(name) {
            // 限制图例文字长度
            return name.length > 10 ? name.slice(0, 10) + '...' : name;
          }
        },
        series: [{
          type: 'pie',
          radius: '50%',
          data: filteredRiskData,
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(0, 0, 0, 0.5)'
            }
          },
          label: {
            formatter: '{b}: {c} ({d}%)',
            overflow: 'truncate'
          }
        }]
      });
    };

    const formatSize = (size) => {
      if (size < 1024) return size + ' B';
      if (size < 1024 * 1024) return (size / 1024).toFixed(2) + ' KB';
      return (size / (1024 * 1024)).toFixed(2) + ' MB';
    };

    const formatRiskLevel = (level) => {
      const levels = {
        low: '低风险',
        medium: '中风险',
        high: '高风险'
      };
      return levels[level] || level;
    };
    const formatPacketType=(type)=>{
      const types={
        request_packet:'请求包',
        response_packet:'响应包'
      }
      return types[type] || type;
    }
   

    const handleDateRangeChange = () => {
      timeRange.value = '' // 清除时间范围选择
      fetchTrafficData()
    }

    const handleSizeChange = (val) => {
      pageSize.value = val;
      currentPage.value = 1; // 重置到第一页
      fetchTrafficData();
    };

    const handleCurrentChange = (val) => {
      currentPage.value = val;
      fetchTrafficData();
    };

    // 添加实时过滤监听
    watch([selectedDateRange, timeRange, selectedProtocol, selectedRiskLevel], () => {
      currentPage.value = 1 // 重置到第一页
      fetchTrafficData()
    }, { deep: true })

    const exportData = async () => {
      try {
        exporting.value = true
        // 准备导出数据
        const exportData = trafficData.value.map(item => ({
          '时间': formatTime(item.timestamp),
          '源IP': `${item.source_ip}:${item.source_port}`,
          '目标IP': `${item.destination_ip}:${item.destination_port}`,
          '协议': item.protocol,
          '数据包大小': formatSize(item.packet_size),
          '流量类型': getTrafficTypeLabel(item.traffic_type),
          '风险等级': formatRiskLevel(item.risk_level),
          '状态码': item.response_code,
          '威胁类型': item.threat_type || '无',
          'Header体': formatHeader(item.header_body),
          'Payload': formatPayload(item.payload)
        }))

        // 创建工作簿
        const wb = XLSX.utils.book_new()
        const ws = XLSX.utils.json_to_sheet(exportData)

        // 设置列宽
        const colWidths = [
          { wch: 20 }, // 时间
          { wch: 25 }, // 源IP
          { wch: 25 }, // 目标IP
          { wch: 10 }, // 协议
          { wch: 15 }, // 数据包大小
          { wch: 15 }, // 流量类型
          { wch: 10 }, // 风险等级
          { wch: 10 }, // 状态
          { wch: 15 }, // 威胁类型
          { wch: 50 }, // Header体
          { wch: 50 }  // Payload
        ]
        ws['!cols'] = colWidths

        // 添加工作表到工作簿
        XLSX.utils.book_append_sheet(wb, ws, '流量数据')

        // 生成文件名（包含当前时间）
        const now = new Date()
        const fileName = `流量数据_${now.getFullYear()}${(now.getMonth() + 1).toString().padStart(2, '0')}${now.getDate().toString().padStart(2, '0')}_${now.getHours().toString().padStart(2, '0')}${now.getMinutes().toString().padStart(2, '0')}.xlsx`

        // 导出文件
        XLSX.writeFile(wb, fileName)
        ElMessage.success('导出成功')
      } catch (error) {
        console.error('导出失败:', error)
        ElMessage.error('导出失败')
      } finally {
        exporting.value = false
      }
    }

    // 在 setup() 函数中添加格式化威胁类型的函数
    const formatThreatType = (threats) => {
      if (!threats) return '无';
      
      try {
        // 处理字符串化的列表，将单引号替换为双引号
        const threatArray = typeof threats === 'string' 
          ? JSON.parse(threats.replace(/'/g, '"')) 
          : threats;
        
        if (!Array.isArray(threatArray)) return '无';
        
        // 格式化每个威胁
        return threatArray.map(threat => {
          if (!threat) return '';
          
          let threatDesc = '';
          
          // 根据威胁类型生成描述
          switch (threat.category) {
            case 'ip':
              threatDesc = `恶意IP(${threat.ip_type}): ${threat.ip_info}`;
              break;
            case 'top10':
              threatDesc = 'TOP10漏洞';
              break;
            case 'webshell':
              threatDesc = 'Webshell攻击';
              break;
            case 'cve':
              threatDesc = 'CVE漏洞';
              break;
            case 'poc':
              threatDesc = 'POC攻击';
              break;
            case 'sensitive':
              threatDesc = '敏感信息泄露';
              break;
            default:
              threatDesc = threat.category;
          }
          
          // 添加置信度和严重程度
          return `${threatDesc} (置信度: ${threat.confidence}, 严重程度: ${formatRiskLevel(threat.severity)})`;
        }).filter(Boolean).join('\n');
      } catch (e) {
        console.error('威胁类型格式化错误:', e);
        return '无';
      }
    };

    onMounted(() => {
      console.log('Component mounted'); // 调试日志
      // 初始化图表
      trendChartInstance = echarts.init(trendChart.value);
      protocolChartInstance = echarts.init(protocolChart.value);

      // 初始化WebSocket连接
      initSocket();

      // 初始加载数据
      fetchTrafficData();
    });

    onUnmounted(() => {
      // 关闭WebSocket连接
      if (socket) {
        socket.disconnect();
      }
      // 销毁图表实例
      if (trendChartInstance) {
        trendChartInstance.dispose();
      }
      if (protocolChartInstance) {
        protocolChartInstance.dispose();
      }
    });

    return {
      showAdvancedFilter,
      filterForm,
      applyFilter,
      selectedDateRange,
      timeRange,
      selectedProtocol,
      selectedRiskLevel,
      trafficData,
      stats,
      trendChart,
      protocolChart,
      detailVisible,
      currentDetail,
      pickerOptions,
      currentPage,
      pageSize,
      total,
      loading,
      exporting,
      currentPageData,
      showDetail,
      handleClose,
      formatPayload,
      formatHeader,
      formatTime,
      formatSize,
      formatRiskLevel,
      formatPacketType,
      handleDateRangeChange,
      handleSizeChange,
      handleCurrentChange,
      getTrafficTypeStyle,
      getTrafficTypeLabel,
      exportData,
      formatThreatType
    };
  }
};
</script>

<style scoped>
.traffic-analyzer {
  padding: 20px;
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.stat-card h3 {
  margin: 0 0 10px 0;
  color: #666;
  font-size: 16px;
}

.number {
  font-size: 24px;
  font-weight: bold;
  color: #1890ff;
}

.number.warning {
  color: #faad14;
}

.number.danger {
  color: #f5222d;
}

.trend {
  font-size: 14px;
  color: #999;
}

.filter-section {
  display: flex;
  gap: 15px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.filter-section .el-date-picker,
.filter-section .el-select {
  width: 200px;
}

.charts-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.chart-card {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.chart-card h3 {
  margin: 0 0 20px 0;
  color: #666;
}

.chart {
  height: 300px;
}

.traffic-table {
  background: white;
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.table-header h3 {
  margin: 0;
  color: #666;
}

.table-container {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid #e8e8e8;
}

th {
  background: #fafafa;
  font-weight: 500;
  color: #666;
}

tr:hover {
  background: #f5f5f5;
}

.risk-tag {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.risk-tag.low {
  background: #f6ffed;
  color: #52c41a;
}

.risk-tag.medium {
  background: #fff7e6;
  color: #faad14;
}

.risk-tag.high {
  background: #fff1f0;
  color: #f5222d;
}

.status-tag {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.status-tag.normal {
  background: #f6ffed;
  color: #52c41a;
}

.status-tag.suspicious {
  background: #fff7e6;
  color: #faad14;
}

.status-tag.malicious {
  background: #fff1f0;
  color: #f5222d;
}

@media (max-width: 768px) {
  .filter-section {
    flex-direction: column;
  }
  
  .filter-section .el-date-picker,
  .filter-section .el-select {
    width: 100%;
  }

  .charts-container {
    grid-template-columns: 1fr;
  }

  .table-container {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
}

.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.detail-content {
  padding: 20px;
}

.detail-row {
  margin-bottom: 15px;
  display: flex;
  align-items: flex-start;
}

.detail-row .label {
  width: 100px;
  font-weight: bold;
  color: #666;
}

.detail-row.payload {
  flex-direction: column;
}

.detail-row.payload pre {
  margin-top: 10px;
  padding: 10px;
  background: #f5f5f5;
  border-radius: 4px;
  max-height: 300px;
  overflow: auto;
  white-space: pre-wrap;
  word-wrap: break-word;
}

:deep(.el-drawer__header) {
  margin-bottom: 0;
  padding: 20px;
  border-bottom: 1px solid #e8e8e8;
}

:deep(.el-drawer__body) {
  padding: 20px;
}

:deep(.el-table) {
  margin-bottom: 20px;
}

:deep(.el-table__empty-block) {
  min-height: 200px;
}

:deep(.el-table__empty-text) {
  line-height: 200px;
}

:deep(.el-pagination) {
  margin-top: 20px;
  justify-content: flex-end;
}

:deep(.el-table__row) {
  transition: background-color 0.3s;
}

:deep(.el-table__row:hover) {
  background-color: #f5f7fa;
}

:deep(.el-table th) {
  background-color: #f5f7fa;
  color: #606266;
  font-weight: 500;
}

:deep(.el-table td) {
  padding: 12px 0;
}

.threat-type {
  margin: 0;
  padding: 10px;
  background: #f5f5f5;
  border-radius: 4px;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: monospace;
  line-height: 1.5;
}
</style>

