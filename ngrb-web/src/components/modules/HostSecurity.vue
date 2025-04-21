<template>
  <div class="host-security">
    <div class="host-list">
      <el-card class="host-card">
        <template #header>
          <div class="card-header">
            <span>主机列表</span>
            <el-button type="primary" @click="refreshHosts">刷新</el-button>
          </div>
        </template>
        <el-table :data="hosts" style="width: 100%" v-loading="loading">
          <el-table-column prop="hostname" label="主机名" />
          <el-table-column prop="ip" label="IP地址" />
          <el-table-column prop="os" label="操作系统" />
          <el-table-column prop="status" label="状态">
            <template #default="scope">
              <el-tag :type="getStatusType(scope.row.status)">
                {{ scope.row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="200">
            <template #default="scope">
              <el-button-group>
                <el-button
                  size="small"
                  @click="showHostDetail(scope.row)"
                >
                  详情
                </el-button>
                <el-button
                  size="small"
                  type="primary"
                  @click="startTrafficCapture(scope.row)"
                >
                  抓包
                </el-button>
              </el-button-group>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <!-- 主机详情抽屉 -->
    <el-drawer
      v-model="detailVisible"
      title="主机详情"
      direction="rtl"
      size="50%"
    >
      <div v-if="currentHost" class="host-detail">
        <div class="detail-section">
          <h3>基本信息</h3>
          <div class="detail-item">
            <span class="label">主机名：</span>
            <span>{{ currentHost.hostname }}</span>
          </div>
          <div class="detail-item">
            <span class="label">IP地址：</span>
            <span>{{ currentHost.ip }}</span>
          </div>
          <div class="detail-item">
            <span class="label">操作系统：</span>
            <span>{{ currentHost.os }}</span>
          </div>
          <div class="detail-item">
            <span class="label">CPU使用率：</span>
            <span>{{ currentHost.cpu_usage }}%</span>
          </div>
          <div class="detail-item">
            <span class="label">内存使用率：</span>
            <span>{{ currentHost.memory_usage }}%</span>
          </div>
        </div>

        <div class="detail-section">
          <h3>安全状态</h3>
          <div class="security-metrics">
            <div class="metric-card" v-for="(metric, index) in securityMetrics" :key="index">
              <div class="metric-value">{{ metric.value }}</div>
              <div class="metric-label">{{ metric.label }}</div>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h3>最近告警</h3>
          <el-timeline>
            <el-timeline-item
              v-for="(alert, index) in currentHost.alerts"
              :key="index"
              :type="getAlertType(alert.level)"
              :timestamp="formatTime(alert.timestamp)"
            >
              {{ alert.message }}
            </el-timeline-item>
          </el-timeline>
        </div>
      </div>
    </el-drawer>

    <!-- 流量捕获对话框 -->
    <el-dialog
      v-model="captureDialogVisible"
      title="流量捕获"
      width="50%"
    >
      <div v-if="currentHost" class="capture-settings">
        <el-form :model="captureForm" label-width="120px">
          <el-form-item label="捕获时长">
            <el-input-number v-model="captureForm.duration" :min="1" :max="60" />
            <span class="unit">分钟</span>
          </el-form-item>
          <el-form-item label="过滤条件">
            <el-input
              v-model="captureForm.filter"
              placeholder="例如: tcp port 80"
            />
          </el-form-item>
          <el-form-item label="保存位置">
            <el-input
              v-model="captureForm.save_path"
              placeholder="保存路径"
            />
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="captureDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="startCapture" :loading="capturing">
            开始捕获
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import axios from 'axios';

export default {
  name: 'HostSecurity',
  setup() {
    const hosts = ref([]);
    const loading = ref(false);
    const detailVisible = ref(false);
    const currentHost = ref(null);
    const captureDialogVisible = ref(false);
    const capturing = ref(false);
    const captureForm = ref({
      duration: 5,
      filter: '',
      save_path: ''
    });

    const fetchHosts = async () => {
      loading.value = true;
      try {
        const response = await axios.get('http://localhost:5000/api/hosts');
        if (response.data.success) {
          hosts.value = response.data.data;
        }
      } catch (error) {
        console.error('获取主机列表失败:', error);
        ElMessage.error('获取主机列表失败');
      } finally {
        loading.value = false;
      }
    };

    const refreshHosts = () => {
      fetchHosts();
    };

    const showHostDetail = (host) => {
      currentHost.value = host;
      detailVisible.value = true;
    };

    const startTrafficCapture = (host) => {
      currentHost.value = host;
      captureDialogVisible.value = true;
    };

    const startCapture = async () => {
      capturing.value = true;
      try {
        const response = await axios.post('http://localhost:5000/api/hosts/capture', {
          host_id: currentHost.value.id,
          ...captureForm.value
        });
        
        if (response.data.success) {
          ElMessage.success('开始捕获流量');
          captureDialogVisible.value = false;
        }
      } catch (error) {
        console.error('启动流量捕获失败:', error);
        ElMessage.error('启动流量捕获失败');
      } finally {
        capturing.value = false;
      }
    };

    const getStatusType = (status) => {
      const types = {
        '在线': 'success',
        '离线': 'danger',
        '未知': 'info'
      };
      return types[status] || 'info';
    };

    const getAlertType = (level) => {
      const types = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info'
      };
      return types[level] || 'info';
    };

    const formatTime = (timestamp) => {
      return new Date(timestamp).toLocaleString();
    };

    const securityMetrics = ref([
      { label: '漏洞数量', value: '12' },
      { label: '恶意进程', value: '2' },
      { label: '异常登录', value: '1' },
      { label: '文件变更', value: '5' }
    ]);

    onMounted(() => {
      fetchHosts();
    });

    return {
      hosts,
      loading,
      detailVisible,
      currentHost,
      captureDialogVisible,
      capturing,
      captureForm,
      securityMetrics,
      refreshHosts,
      showHostDetail,
      startTrafficCapture,
      startCapture,
      getStatusType,
      getAlertType,
      formatTime
    };
  }
};
</script>

<style scoped>
.host-security {
  padding: 20px;
}

.host-list {
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.host-detail {
  padding: 20px;
}

.detail-section {
  margin-bottom: 30px;
}

.detail-section h3 {
  margin: 0 0 15px 0;
  color: #303133;
  font-size: 16px;
}

.detail-item {
  display: flex;
  margin-bottom: 10px;
}

.detail-item .label {
  width: 100px;
  color: #606266;
}

.security-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 15px;
  margin-top: 15px;
}

.metric-card {
  background: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  text-align: center;
}

.metric-value {
  font-size: 24px;
  font-weight: bold;
  color: #409eff;
  margin-bottom: 5px;
}

.metric-label {
  color: #606266;
  font-size: 14px;
}

.capture-settings {
  padding: 20px 0;
}

.unit {
  margin-left: 10px;
  color: #606266;
}

:deep(.el-timeline-item__node) {
  background-color: #409eff;
}

:deep(.el-timeline-item__node.is-danger) {
  background-color: #f56c6c;
}

:deep(.el-timeline-item__node.is-warning) {
  background-color: #e6a23c;
}

:deep(.el-timeline-item__node.is-info) {
  background-color: #909399;
}
</style>