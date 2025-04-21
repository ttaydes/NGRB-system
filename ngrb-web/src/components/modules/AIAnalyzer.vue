<template>
  <div class="ai-analyzer">
    <div class="analysis-section">
      <el-card class="input-card">
        <template #header>
          <div class="card-header">
            <span>AI安全分析</span>
          </div>
        </template>
        <div class="input-content">
          <el-input
            v-model="analysisInput"
            type="textarea"
            :rows="6"
            placeholder="请输入需要分析的安全事件、日志或威胁情报..."
          />
          <div class="analysis-options">
            <el-select v-model="analysisType" placeholder="分析类型">
              <el-option label="流量分析" value="traffic" />
              <el-option label="文件分析" value="file" />
              <el-option label="主机安全" value="host" />
              <el-option label="威胁情报" value="threat" />
            </el-select>
            <el-button type="primary" @click="analyze" :loading="analyzing">
              开始分析
            </el-button>
          </div>
        </div>
      </el-card>

      <el-card class="result-card" v-if="analysisResult">
        <template #header>
          <div class="card-header">
            <span>分析结果</span>
            <el-tag :type="getConfidenceType(analysisResult.confidence)">
              置信度: {{ analysisResult.confidence }}%
            </el-tag>
          </div>
        </template>
        <div class="result-content">
          <div class="result-section">
            <h3>分析摘要</h3>
            <p>{{ analysisResult.summary }}</p>
          </div>
          
          <div class="result-section" v-if="analysisResult.threats && analysisResult.threats.length > 0">
            <h3>威胁分析</h3>
            <el-table :data="analysisResult.threats" style="width: 100%">
              <el-table-column prop="type" label="威胁类型" width="120" />
              <el-table-column prop="description" label="描述" />
              <el-table-column prop="severity" label="严重程度" width="100">
                <template #default="scope">
                  <el-tag :type="getSeverityType(scope.row.severity)">
                    {{ scope.row.severity }}
                  </el-tag>
                </template>
              </el-table-column>
            </el-table>
          </div>
          
          <div class="result-section" v-if="analysisResult.recommendations && analysisResult.recommendations.length > 0">
            <h3>建议措施</h3>
            <el-collapse>
              <el-collapse-item
                v-for="(rec, index) in analysisResult.recommendations"
                :key="index"
                :title="rec.title"
              >
                <div class="recommendation-content">
                  <p>{{ rec.description }}</p>
                  <div class="recommendation-steps" v-if="rec.steps">
                    <ol>
                      <li v-for="(step, stepIndex) in rec.steps" :key="stepIndex">
                        {{ step }}
                      </li>
                    </ol>
                  </div>
                </div>
              </el-collapse-item>
            </el-collapse>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue';
import { ElMessage } from 'element-plus';
import axios from 'axios';

export default {
  name: 'AIAnalyzer',
  setup() {
    const analysisInput = ref('');
    const analysisType = ref('traffic');
    const analysisResult = ref(null);
    const analyzing = ref(false);

    const analyze = async () => {
      if (!analysisInput.value.trim()) {
        ElMessage.warning('请输入需要分析的内容');
        return;
      }

      analyzing.value = true;
      try {
        const response = await axios.post('http://localhost:5000/api/ai/analyze', {
          content: analysisInput.value,
          type: analysisType.value
        });

        if (response.data.success) {
          analysisResult.value = response.data.data;
        } else {
          ElMessage.error(response.data.message || '分析失败');
        }
      } catch (error) {
        console.error('AI分析错误:', error);
        ElMessage.error('分析请求失败');
      } finally {
        analyzing.value = false;
      }
    };

    const getConfidenceType = (confidence) => {
      if (confidence >= 80) return 'success';
      if (confidence >= 60) return 'warning';
      return 'danger';
    };

    const getSeverityType = (severity) => {
      const types = {
        '低': 'success',
        '中': 'warning',
        '高': 'danger'
      };
      return types[severity] || 'info';
    };

    return {
      analysisInput,
      analysisType,
      analysisResult,
      analyzing,
      analyze,
      getConfidenceType,
      getSeverityType
    };
  }
};
</script>

<style scoped>
.ai-analyzer {
  padding: 20px;
}

.analysis-section {
  max-width: 800px;
  margin: 0 auto;
}

.input-card, .result-card {
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.input-content {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.analysis-options {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

.result-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.result-section h3 {
  margin: 0 0 10px 0;
  color: #303133;
}

.recommendation-content {
  padding: 10px 0;
}

.recommendation-steps {
  margin-top: 10px;
  padding-left: 20px;
}

.recommendation-steps ol {
  margin: 0;
  padding-left: 20px;
}

.recommendation-steps li {
  margin-bottom: 5px;
}
</style> 