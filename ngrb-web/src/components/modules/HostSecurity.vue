<template>
  <div class="host-security">
    <el-card class="host-list">
      <template #header>
        <div class="card-header">
          <span>主机列表</span>
          <el-button type="primary" @click="refreshHosts">刷新</el-button>
        </div>
      </template>
      
      <el-table :data="hosts" style="width: 100%">
        <el-table-column prop="hostname" label="主机名" />
        <el-table-column prop="ip_address" label="IP地址" />
        <el-table-column prop="os_type" label="操作系统" />
        <el-table-column prop="status" label="状态">
          <template #default="scope">
            <el-tag :type="scope.row.status === 'online' ? 'success' : 'danger'">
              {{ scope.row.status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作">
          <template #default="scope">
            <el-button-group>
              <el-button size="small" @click="startBasicScan(scope.row)">
                基础扫描
              </el-button>
          
            </el-button-group>
            <el-button size="small" @click="showDetail(scope.row)">
              详情
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 扫描结果对话框 -->
    <el-dialog
      v-model="scanDialogVisible"
      title="扫描结果"
      width="70%"
      class="detail-dialog"
    >
      <el-tabs v-model="activeTab" class="detail-tabs">
        <el-tab-pane label="进程信息" name="processes">
          <div class="table-container">
            <el-table :data="processInfo" height="800">
              <el-table-column prop="process_name" label="进程名" />
              <el-table-column prop="pid" label="PID" />
              <el-table-column prop="user" label="用户" />
              <el-table-column prop="cpu_usage" label="CPU使用率">
                <template #default="scope">
                  {{ scope.row.cpu_usage }}%
                </template>
              </el-table-column>
              <el-table-column prop="memory_usage" label="内存使用率">
                <template #default="scope">
                  {{ scope.row.memory_usage }}%
                </template>
              </el-table-column>
              <el-table-column label="网络连接">
                <template #default="scope">
                  <el-popover
                    placement="right"
                    :width="400"
                    trigger="click"
                  >
                    <template #reference>
                      <el-button size="small" type="primary" plain>
                        查看连接 ({{ scope.row.connections?.length || 0 }})
                      </el-button>
                    </template>
                    <div v-if="scope.row.connections && scope.row.connections.length > 0">
                      <div v-for="(conn, index) in scope.row.connections" :key="index" class="connection-item">
                        <div><strong>本地地址:</strong> {{ conn.local_addr || '-' }}</div>
                        <div><strong>远程地址:</strong> {{ conn.remote_addr || '-' }}</div>
                        <div><strong>状态:</strong> {{ conn.status }}</div>
                        <div><strong>类型:</strong> {{ conn.type }}</div>
                        <el-divider v-if="index < scope.row.connections.length - 1" />
                      </div>
                    </div>
                    <div v-else>
                      无网络连接
                    </div>
                  </el-popover>
                </template>
              </el-table-column>
            </el-table>
          </div>
        </el-tab-pane>
        
        <el-tab-pane label="服务信息" name="services">
          <div class="table-container">
            <el-table :data="serviceInfo" height="800">
              <el-table-column prop="service_name" label="服务名" />
              <el-table-column prop="status" label="状态" />
              <el-table-column prop="start_type" label="启动类型" />
              <el-table-column prop="display_name" label="显示名" />
              <el-table-column prop="description" label="描述" />
            </el-table>
          </div>
        </el-tab-pane>
        
        <el-tab-pane label="安全扫描" name="security">
          <div class="table-container">
            <el-table :data="securityFindings" height="800">
              <el-table-column prop="scan_type" label="类型" />
              <el-table-column prop="status" label="状态" />
              <el-table-column prop="findings" label="扫描结果">
                <template #default="scope">
                  <div v-if="scope.row.findings">
                    <div v-if="typeof scope.row.findings === 'string'">
                      {{ scope.row.findings }}
                    </div>
                    <div v-else>
                      <div v-for="(value, key) in scope.row.findings" :key="key" class="finding-item">
                        <strong>{{ key }}:</strong>
                        <span v-if="typeof value === 'object'">
                          {{ JSON.stringify(value, null, 2) }}
                        </span>
                        <span v-else>{{ value }}</span>
                      </div>
                    </div>
                  </div>
                  <span v-else>-</span>
                </template>
              </el-table-column>
              <el-table-column prop="risk_level" label="风险等级">
                <template #default="scope">
                  <el-tag :type="getRiskLevelType(scope.row.risk_level)">
                    {{ scope.row.risk_level }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="scan_time" label="扫描时间" />
            </el-table>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

export default {
  name: 'HostSecurity',
  setup() {
    const hosts = ref([])
    const scanDialogVisible = ref(false)
    const activeTab = ref('processes')
    const processInfo = ref([])
    const serviceInfo = ref([])
    const securityFindings = ref([])
    



    const showDetail = async (host) => {
      try {
        activeTab.value = 'processes'
        // 获取进程信息
        const processResponse = await axios.get(`http://127.0.0.1:5000/api/hosts/${host.id}/processes`)
        processInfo.value = processResponse.data
        
        // 获取服务信息
        const serviceResponse = await axios.get(`http://127.0.0.1:5000/api/hosts/${host.id}/services`)
        serviceInfo.value = serviceResponse.data
        
        // 获取安全扫描结果
        const scanResponse = await axios.get(`http://127.0.0.1:5000/api/hosts/${host.id}/scans`)
        securityFindings.value = scanResponse.data
        
        scanDialogVisible.value = true
      } catch (error) {
        ElMessage.error('获取详情失败')
      }
    }

    const refreshHosts = async () => {
      try {
        const response = await axios.get('http://127.0.0.1:5000/api/hosts')
        hosts.value = response.data
      } catch (error) {
        ElMessage.error('获取主机列表失败')
      }
    }

    const startBasicScan = async (host) => {
      try {
        await axios.post(`http://127.0.0.1:5000/api/hosts/${host.id}/scan`, {
          scan_type: 'basic'
        })
        ElMessage.success('基础扫描已启动')
      } catch (error) {
        ElMessage.error('启动扫描失败')
      }
    }

   

    const startLogAnalysis = async (host) => {
      try {
        await axios.post(`http://127.0.0.1:5000/api/hosts/${host.id}/scan`, {
          scan_type: 'logs'
        })
        ElMessage.success('日志分析已启动')
      } catch (error) {
        ElMessage.error('启动分析失败')
      }
    }

    const getRiskLevelType = (level) => {
      const types = {
        high: 'danger',
        medium: 'warning',
        low: 'info'
      }
      return types[level] || 'info'
    }

    onMounted(() => {
      refreshHosts()
    })

    return {
      hosts,
      scanDialogVisible,
      activeTab,
      processInfo,
      serviceInfo,
      securityFindings,
      refreshHosts,
      startBasicScan,
      startLogAnalysis,
      getRiskLevelType,
      showDetail
    }
  }
}
</script>

<style scoped>
.host-security {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.host-list {
  margin-bottom: 20px;
}

.detail-dialog :deep(.el-dialog__body) {
  padding: 20px;
  max-height: 70vh;
  overflow: hidden;
}

.detail-tabs {
  height: 100%;
}

.table-container {
  height: 100%;
  overflow: hidden;
}

:deep(.el-table) {
  height: 100%;
}

:deep(.el-table__body-wrapper) {
  overflow-y: auto;
}

:deep(.el-tabs__content) {
  height: calc(100% - 40px);
  overflow: hidden;
}

:deep(.el-tab-pane) {
  height: 100%;
}

.finding-item {
  margin-bottom: 4px;
  white-space: pre-wrap;
  word-break: break-word;
}

.finding-item strong {
  margin-right: 8px;
  color: #606266;
}

.connection-item {
  padding: 8px;
  font-size: 14px;
}

.connection-item div {
  margin-bottom: 4px;
}

.connection-item strong {
  color: #606266;
  margin-right: 8px;
}
</style>