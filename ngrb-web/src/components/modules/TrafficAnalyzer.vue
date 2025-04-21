<template>
  
  <div class="traffic-analyzer">
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
        <h3>协议分布</h3>
        <div class="chart" ref="protocolChart"></div>
      </div>
    </div>

    <div class="traffic-table">
      <h3>实时流量</h3>
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
          <el-table-column prop="risk_level" label="风险等级" width="120">
            <template #default="scope">
              <template v-if="scope && scope.row">
                <span :class="['risk-tag', scope.row.risk_level]">
                  {{ formatRiskLevel(scope.row.risk_level) }}
                </span>
              </template>
            </template>
          </el-table-column>
          <el-table-column prop="status" label="状态" width="120">
            <template #default="scope">
              <template v-if="scope && scope.row">
                <span :class="['status-tag', scope.row.status]">
                  {{ formatStatus(scope.row.status) }}
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
          <span>{{ currentDetail.threat_type || '无' }}</span>
        </div>
        <div class="detail-row">
          <span class="label">状态：</span>
          <span :class="['status-tag', currentDetail.status]">
            {{ formatStatus(currentDetail.status) }}
          </span>
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
import { ref, onMounted, onUnmounted, computed } from 'vue';
import * as echarts from 'echarts';
import axios from 'axios';
import io from 'socket.io-client';
import { ElMessage } from 'element-plus';

export default {
  name: 'TrafficAnalyzer',
  setup() {
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

    const currentPageData = computed(() => {
      console.log('Current traffic data:', trafficData.value); // 调试日志
      if (!Array.isArray(trafficData.value) || trafficData.value.length === 0) {
        return [];
      }
      const start = (currentPage.value - 1) * pageSize.value;
      const end = start + pageSize.value;
      return trafficData.value.slice(start, end);
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
        const decoded = atob(payload);
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
      loading.value = true;
      try {
        const params = new URLSearchParams();
        params.append('limit', '1000');
        
        if (selectedDateRange.value && selectedDateRange.value.length === 2) {
          // 格式化日期为 YYYY-MM-DD
          const formatDate = (date) => {
            const d = new Date(date);
            const year = d.getFullYear();
            const month = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            return `${year}-${month}-${day}`;
          };
          
          params.append('start_date', formatDate(selectedDateRange.value[0]));
          params.append('end_date', formatDate(selectedDateRange.value[1]));
        } else {
          params.append('time_range', timeRange.value);
        }
        
        if (selectedProtocol.value) {
          params.append('protocol', selectedProtocol.value);
        }
        if (selectedRiskLevel.value) {
          params.append('risk_level', selectedRiskLevel.value);
        }

        console.log('Fetching data with params:', params.toString()); // 调试日志
        const response = await axios.get(`http://localhost:5000/api/traffic?${params.toString()}`);
        console.log('Received response:', response.attackStats); // 调试日志

        if (response.data && Array.isArray(response.data.traffic)) {
          trafficData.value = response.data.traffic.map(item => ({
            ...item,
            timestamp: new Date(item.timestamp).toISOString() // 确保时间戳格式正确
          }));
          total.value = response.data.total || 0;
          stats.value = {
            total: response.data.total || 0,
            suspicious: response.data.suspicious || 0,
            malicious: response.data.malicious || 0
          };
          console.log('Processed traffic data:', trafficData.value); // 调试日志
        } else {
          console.warn('Invalid response format:', response.data); // 调试日志
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
        xAxis: {
          type: 'category',
          data: data.hourly_stats.map(item => item.hour)
        },
        yAxis: {
          type: 'value'
        },
        series: [{
          data: data.hourly_stats.map(item => item.count),
          type: 'line',
          smooth: true
        }]
      });

      // 更新协议分布图
      protocolChartInstance.setOption({
        tooltip: {
          trigger: 'item'
        },
        series: [{
          type: 'pie',
          radius: '50%',
          data: data.protocol_stats.map(item => ({
            name: item.protocol,
            value: item.count
          }))
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

    const formatStatus = (status) => {
      const statusMap = {
        normal: '正常',
        suspicious: '可疑',
        malicious: '恶意'
      };
      return statusMap[status] || status;
    };

    const handleDateRangeChange = () => {
      timeRange.value = '';
      fetchTrafficData();
    };

    const handleSizeChange = (val) => {
      pageSize.value = val;
      currentPage.value = 1;
    };

    const handleCurrentChange = (val) => {
      currentPage.value = val;
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
      showDetail,
      handleClose,
      formatTime,
      formatSize,
      formatRiskLevel,
      formatStatus,
      formatPayload,
      fetchTrafficData,
      pickerOptions,
      handleDateRangeChange,
      currentPage,
      pageSize,
      total,
      currentPageData,
      handleSizeChange,
      handleCurrentChange,
      loading
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

.traffic-table h3 {
  margin: 0 0 20px 0;
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
</style> 