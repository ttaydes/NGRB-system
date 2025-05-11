<template>
  <div class="file-threat-analyzer">
    <el-card class="upload-section">
      <template #header>
        <div class="card-header">
          <span>文件威胁分析</span>
          <el-radio-group v-model="analysisMode" size="small">
            <el-radio-button label="single">单文件分析</el-radio-button>
            <el-radio-button label="batch">批量分析</el-radio-button>
          </el-radio-group>
        </div>
      </template>
      
      <el-upload
        v-if="analysisMode === 'single'"
        class="upload-demo"
        drag
        :action="uploadUrl"
        :on-success="handleUploadSuccess"
        :on-error="handleUploadError"
        :show-file-list="false"
      >
        <el-icon class="el-icon--upload"><upload-filled /></el-icon>
        <div class="el-upload__text">
          拖曳文件到这 <em>点击上传</em>
        </div>
        <template #tip>
          <div class="el-upload__tip">
            支持的文件类型: .exe, .dll, .pdf, .doc, .docx, .xls, .xlsx, .zip, .rar等
          </div>
        </template>
      </el-upload>

      <el-upload
        v-else
        class="upload-demo"
        drag
        multiple
        :action="uploadUrl"
        :on-success="handleUploadSuccess"
        :on-error="handleUploadError"
        :file-list="fileList"
      >
        <el-icon class="el-icon--upload"><upload-filled /></el-icon>
        <div class="el-upload__text">
          拖曳文件到这 <em>点击上传</em>
        </div>
        <template #tip>
          <div class="el-upload__tip">
            支持的文件类型: .exe, .dll, .pdf, .doc, .docx, .xls, .xlsx, .zip, .rar
          </div>
        </template>
      </el-upload>
    </el-card>

    <el-card class="analysis-results" v-if="analysisResults.length > 0">
      <template #header>
        <div class="card-header">
          <span>分析结果</span>
          <el-button type="primary" @click="exportReport">导出报告</el-button>
        </div>
      </template>

      <el-table :data="analysisResults" style="width: 100%">
        <el-table-column prop="filename" label="文件名" width="200" />
        <el-table-column prop="sha256" label="SHA256" width="300" />
        <el-table-column prop="fileType" label="文件类型" width="120" />
        <el-table-column prop="fileSize" label="大小" width="120">
          <template #default="scope">
            {{ formatFileSize(scope.row.fileSize) }}
          </template>
        </el-table-column>
        <el-table-column prop="threatLevel" label="威胁等级" width="120">
          <template #default="scope">
            <el-tag :type="getThreatLevelType(scope.row.threatLevel)">
              {{ scope.row.threatLevel }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="detectionTime" label="检测时间" width="180">
          <template #default="scope">
            {{ formatDate(scope.row.detectionTime) }}
          </template>
        </el-table-column>
        <el-table-column fixed="right" label="操作" width="120">
          <template #default="scope">
            <el-button link type="primary" @click="viewDetails(scope.row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 文件详情对话框 -->
    <el-dialog
      v-model="detailsVisible"
      :title="selectedFile ? selectedFile.filename + ' 分析详情' : '文件分析详情'"
      width="60%"
    >
      <div v-if="selectedFile" class="file-details">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="文件名">{{ selectedFile.filename }}</el-descriptions-item>
          <el-descriptions-item label="SHA256">{{ selectedFile.sha256 }}</el-descriptions-item>
          <el-descriptions-item label="文件类型">{{ selectedFile.fileType }}</el-descriptions-item>
          <el-descriptions-item label="文件大小">{{ formatFileSize(selectedFile.fileSize) }}</el-descriptions-item>
          <el-descriptions-item label="威胁等级">
            <el-tag :type="getThreatLevelType(selectedFile.threatLevel)">
              {{ selectedFile.threatLevel }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="yara分析结果">{{ selectedFile.yaraResult }}</el-descriptions-item>
          <el-descriptions-item label="微步情报API结果">{{ selectedFile.apiResult }}</el-descriptions-item>
          <el-descriptions-item label="检测时间">{{ formatDate(selectedFile.detectionTime) }}</el-descriptions-item>
        </el-descriptions>

       
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'

export default {
  name: 'FileThreatAnalyzer',
  components: {
    UploadFilled
  },
  setup() {
    const analysisMode = ref('single')
    const fileList = ref([])
    const analysisResults = ref([])
    const detailsVisible = ref(false)
    const selectedFile = ref(null)
    const uploadUrl = 'http://localhost:5000/api/file/analyze'

    const handleUploadSuccess = (response, file) => {
      if (response.success) {
        ElMessage.success(`${file.name} 分析成功`)
        if (Array.isArray(response.data)) {
          analysisResults.value.push(...response.data)
        } else {
          analysisResults.value.push(response.data)
        }
      } else {
        ElMessage.error(`${file.name} 分析失败: ${response.message}`)
      }
    }

    const handleUploadError = (error, file) => {
      ElMessage.error(`${file.name} 上传失败: ${error.message}`)
    }


    const formatFileSize = (size) => {
      if (size < 1024) return size + ' B'
      if (size < 1024 * 1024) return (size / 1024).toFixed(2) + ' KB'
      return (size / (1024 * 1024)).toFixed(2) + ' MB'
    }

    const getThreatLevelType = (level) => {
      const types = {
        'malicious': 'danger',
        'suspicious': 'warning',
        'clean': 'success'
      }
      return types[level] || 'info'
    }

    const formatDate = (dateStr) => {
      return new Date(dateStr).toLocaleString()
    }

    const viewDetails = (file) => {
      selectedFile.value = file
      detailsVisible.value = true
    }

    const exportReport = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/file/export-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ results: analysisResults.value })
        })
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = 'file_analysis_report.xlsx'
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        ElMessage.success('报告导出成功')
      } catch (error) {
        ElMessage.error('导出报告失败')
      }
    }

    return {
      analysisMode,
      fileList,
      analysisResults,
      detailsVisible,
      selectedFile,
      uploadUrl,
      handleUploadSuccess,
      handleUploadError,
      formatFileSize,
      getThreatLevelType,
      formatDate,
      viewDetails,
      exportReport
    }
  }
}
</script>

<style scoped>
.file-threat-analyzer {
  padding: 20px;
}

.upload-section {
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.el-upload__tip {
  margin-top: 10px;
  color: #909399;
}

.analysis-results {
  margin-top: 20px;
}

.file-details {
  padding: 20px;
}

.detection-results {
  margin-top: 20px;
}

.detection-results h3 {
  margin-bottom: 15px;
  color: #606266;
}
</style>