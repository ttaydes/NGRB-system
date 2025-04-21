<template>
  <div class="threat-intelligence">
    <el-tabs v-model="activeTab">
      <el-tab-pane label="情报上传" name="upload">
        <el-card class="upload-section">
          <template #header>
            <div class="card-header">
              <span>威胁情报上传</span>
            </div>
          </template>
          
          <el-form :model="uploadForm" label-width="120px">
            <el-form-item label="来源类型">
              <el-select v-model="uploadForm.sourceType">
                <el-option label="文件上传" value="file" />
                <el-option label="URL导入" value="url" />
                <el-option label="手动输入" value="manual" />
              </el-select>
            </el-form-item>

            <template v-if="uploadForm.sourceType === 'file'">
              <el-upload
                class="intelligence-upload"
                drag
                multiple
                action="/api/threat-intelligence/upload"
                :on-success="handleUploadSuccess"
                :on-error="handleUploadError"
                :before-upload="beforeUpload"
              >
                <el-icon class="el-icon--upload"><upload-filled /></el-icon>
                <div class="el-upload__text">
                  拖拽文件到此处或<em>点击上传</em>
                </div>
                <template #tip>
                  <div class="el-upload__tip">
                    支持的文件格式: CSV, JSON, STIX
                  </div>
                </template>
              </el-upload>
            </template>

            <template v-if="uploadForm.sourceType === 'url'">
              <el-form-item label="情报源URL">
                <el-input v-model="uploadForm.feedUrl" placeholder="请输入威胁情报源URL" />
              </el-form-item>
              <el-form-item>
                <el-button type="primary" @click="fetchFromUrl">获取情报</el-button>
              </el-form-item>
            </template>

            <template v-if="uploadForm.sourceType === 'manual'">
              <el-form-item label="情报类型">
                <el-select v-model="uploadForm.intelligenceType">
                  <el-option label="IP地址" value="ip" />
                  <el-option label="域名" value="domain" />
                  <el-option label="文件哈希" value="file" />
                  <el-option label="URL" value="url" />
                </el-select>
              </el-form-item>
              <el-form-item label="情报值">
                <el-input v-model="uploadForm.value" placeholder="请输入情报值" />
              </el-form-item>
              <el-form-item label="威胁等级">
                <el-select v-model="uploadForm.threatLevel">
                  <el-option label="高危" value="high" />
                  <el-option label="中危" value="medium" />
                  <el-option label="低危" value="low" />
                </el-select>
              </el-form-item>
              <el-form-item label="描述">
                <el-input
                  v-model="uploadForm.description"
                  type="textarea"
                  placeholder="请输入威胁描述"
                />
              </el-form-item>
              <el-form-item>
                <el-button type="primary" @click="addManualIntelligence">添加情报</el-button>
              </el-form-item>
            </template>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="情报管理" name="management">
        <el-card class="management-section">
          <template #header>
            <div class="card-header">
              <div class="header-left">
                <span>情报数据库</span>
                <el-select v-model="filterType" placeholder="按类型筛选" style="margin-left: 20px">
                  <el-option label="全部" value="" />
                  <el-option label="IP地址" value="ip" />
                  <el-option label="域名" value="domain" />
                  <el-option label="文件哈希" value="file" />
                  <el-option label="URL" value="url" />
                </el-select>
              </div>
              <div class="header-right">
                <el-button type="primary" @click="exportIntelligence">导出</el-button>
              </div>
            </div>
          </template>

          <el-table :data="filteredIntelligence" style="width: 100%">
            <el-table-column prop="type" label="类型" width="120" />
            <el-table-column prop="value" label="情报值" min-width="200" />
            <el-table-column prop="threatLevel" label="威胁等级" width="120">
              <template #default="scope">
                <el-tag :type="getThreatLevelType(scope.row.threatLevel)">
                  {{ getThreatLevelLabel(scope.row.threatLevel) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="source" label="来源" width="120" />
            <el-table-column prop="lastUpdated" label="最后更新" width="180">
              <template #default="scope">
                {{ formatDate(scope.row.lastUpdated) }}
              </template>
            </el-table-column>
            <el-table-column fixed="right" label="操作" width="120">
              <template #default="scope">
                <el-button link type="primary" @click="viewDetails(scope.row)">详情</el-button>
                <el-button link type="danger" @click="deleteIntelligence(scope.row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 详情对话框 -->
    <el-dialog
      v-model="detailsVisible"
      title="情报详情"
      width="60%"
    >
      <div v-if="selectedIntelligence" class="intelligence-details">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="类型">{{ getTypeLabel(selectedIntelligence.type) }}</el-descriptions-item>
          <el-descriptions-item label="情报值">{{ selectedIntelligence.value }}</el-descriptions-item>
          <el-descriptions-item label="威胁等级">
            <el-tag :type="getThreatLevelType(selectedIntelligence.threatLevel)">
              {{ getThreatLevelLabel(selectedIntelligence.threatLevel) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="来源">{{ selectedIntelligence.source }}</el-descriptions-item>
          <el-descriptions-item label="最后更新">
            {{ formatDate(selectedIntelligence.lastUpdated) }}
          </el-descriptions-item>
          <el-descriptions-item label="描述">
            {{ selectedIntelligence.description }}
          </el-descriptions-item>
        </el-descriptions>

        <div class="related-events" v-if="selectedIntelligence.relatedEvents">
          <h3>相关事件</h3>
          <el-timeline>
            <el-timeline-item
              v-for="event in selectedIntelligence.relatedEvents"
              :key="event.id"
              :timestamp="formatDate(event.timestamp)"
              :type="event.type === 'alert' ? 'danger' : 'primary'"
            >
              {{ event.description }}
            </el-timeline-item>
          </el-timeline>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'

export default {
  name: 'ThreatIntelligence',
  components: {
    UploadFilled
  },
  setup() {
    const activeTab = ref('upload')
    const uploadForm = ref({
      sourceType: 'file',
      feedUrl: '',
      intelligenceType: 'ip',
      value: '',
      threatLevel: 'medium',
      description: ''
    })
    const filterType = ref('')
    const intelligence = ref([])
    const detailsVisible = ref(false)
    const selectedIntelligence = ref(null)

    const filteredIntelligence = computed(() => {
      if (!filterType.value) return intelligence.value
      return intelligence.value.filter(item => item.type === filterType.value)
    })

    const handleUploadSuccess = (response, file) => {
      ElMessage.success(`${file.name} 上传成功`)
      fetchIntelligence()
    }

    const handleUploadError = (error, file) => {
      ElMessage.error(`${file.name} 上传失败`)
    }

    const beforeUpload = (file) => {
      const allowedTypes = ['text/csv', 'application/json', 'application/xml']
      if (!allowedTypes.includes(file.type)) {
        ElMessage.error('不支持的文件类型')
        return false
      }
      return true
    }

    const fetchFromUrl = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/threat-intelligence', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ url: uploadForm.value.feedUrl })
        })
        if (response.ok) {
          ElMessage.success('情报获取成功')
          fetchIntelligence()
        } else {
          throw new Error('获取情报失败')
        }
      } catch (error) {
        ElMessage.error(error.message)
      }
    }

    const addManualIntelligence = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/threat-intelligence', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            type: uploadForm.value.intelligenceType,
            value: uploadForm.value.value,
            threatLevel: uploadForm.value.threatLevel,
            description: uploadForm.value.description
          })
        })
        if (response.ok) {
          ElMessage.success('情报添加成功')
          fetchIntelligence()
          // 重置表单
          uploadForm.value.value = ''
          uploadForm.value.description = ''
        } else {
          throw new Error('添加情报失败')
        }
      } catch (error) {
        ElMessage.error(error.message)
      }
    }

    const fetchIntelligence = async () => {
      try {
        const response = await fetch('/api/threat-intelligence/list')
        const data = await response.json()
        intelligence.value = data
      } catch (error) {
        ElMessage.error('获取情报数据失败')
      }
    }

    const deleteIntelligence = async (item) => {
      try {
        const response = await fetch(`/api/threat-intelligence/delete/${item.id}`, {
          method: 'DELETE'
        })
        if (response.ok) {
          ElMessage.success('情报删除成功')
          fetchIntelligence()
        } else {
          throw new Error('删除情报失败')
        }
      } catch (error) {
        ElMessage.error(error.message)
      }
    }

    const viewDetails = (item) => {
      selectedIntelligence.value = item
      detailsVisible.value = true
    }

    const exportIntelligence = async () => {
      try {
        const response = await fetch('/api/threat-intelligence/export')
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = 'threat_intelligence.xlsx'
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        ElMessage.success('情报导出成功')
      } catch (error) {
        ElMessage.error('导出情报失败')
      }
    }

    const getThreatLevelType = (level) => {
      const types = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'success'
      }
      return types[level.toLowerCase()] || 'info'
    }

    const getThreatLevelLabel = (level) => {
      const labels = {
        'high': '高危',
        'medium': '中危',
        'low': '低危'
      }
      return labels[level.toLowerCase()] || level
    }

    const getTypeLabel = (type) => {
      const labels = {
        'ip': 'IP地址',
        'domain': '域名',
        'file': '文件哈希',
        'url': 'URL'
      }
      return labels[type] || type
    }

    const formatDate = (dateStr) => {
      return new Date(dateStr).toLocaleString()
    }

    // 组件挂载时获取情报数据
    fetchIntelligence()

    return {
      activeTab,
      uploadForm,
      filterType,
      filteredIntelligence,
      detailsVisible,
      selectedIntelligence,
      handleUploadSuccess,
      handleUploadError,
      beforeUpload,
      fetchFromUrl,
      addManualIntelligence,
      deleteIntelligence,
      viewDetails,
      exportIntelligence,
      getThreatLevelType,
      getThreatLevelLabel,
      getTypeLabel,
      formatDate
    }
  }
}
</script>

<style scoped>
.threat-intelligence {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-left {
  display: flex;
  align-items: center;
}

.upload-section,
.management-section {
  margin-bottom: 20px;
}

.intelligence-upload {
  width: 100%;
}

.el-upload__tip {
  margin-top: 10px;
  color: #909399;
}

.intelligence-details {
  padding: 20px;
}

.related-events {
  margin-top: 20px;
}

.related-events h3 {
  margin-bottom: 15px;
  color: #606266;
}
</style>