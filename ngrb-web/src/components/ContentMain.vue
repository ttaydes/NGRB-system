<template>
  <div class="layout">
    <div class="sidebar">
      <div class="system-title">
        <div class="logo">
          <span class="logo-icon">🛡️</span>
          <span class="logo-text">NGRB威胁分析系统</span>
        </div>
      </div>
      <div class="nav-section">
        <div class="nav-header">
          <h3>功能导航</h3>
        </div>
        <ul class="menu-list">
          <li v-for="(item, index) in menuItems" :key="index">
            <button 
              class="menu-item" 
              :class="{ active: currentMenuIndex === index }"
              @click="handleMenuClick(index)"
            >
              <span class="menu-icon">{{ getMenuIcon(index) }}</span>
              <span class="menu-text">{{ item }}</span>
            </button>
          </li>
        </ul>
      </div>
    </div>
    <div class="main-content">
      <HeaderBar :buttons="currentModule.buttons" @button-click="handleButtonClick" />
      <div class="content">
        <div class="content-header">
          <div class="header-left">
            <h2>{{ currentModule.title }}</h2>
            <div class="breadcrumb">
              <span>首页</span>
              <span class="separator">/</span>
              <span class="current">{{ currentModule.title }}</span>
            </div>
          </div>
        </div>
        <div class="content-body">
          <component :is="currentModule.component" :showMap="showNetworkMap" />
        </div>
      </div>
    </div>

    <!-- 历史文件分析记录对话框 -->
    <el-dialog
      v-model="showHistoryDialog"
      title="历史文件分析记录"
      width="80%"
    >
      <el-table :data="fileHistory" style="width: 100%">
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
            <el-button link type="primary" @click="viewFileDetails(scope.row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue';
import HeaderBar from './HeaderBar.vue';
import SituationAwareness from './modules/SituationAwareness.vue';
import TrafficAnalyzer from './modules/TrafficAnalyzer.vue';
import FileThreatAnalysis from './modules/FileThreatAnalyzer.vue';
import AIAnalysis from './modules/AIAnalyzer.vue';
import HostSecurity from './modules/HostSecurity.vue';
import ThreatIntelligencer from "./modules/ThreatIntelligence.vue"
import { ElMessage } from 'element-plus';

const currentMenuIndex = ref(0);
const showNetworkMap = ref(false);
const showHistoryDialog = ref(false);
const fileHistory = ref([]);

const menuItems = [
  "态势感知", "流量分析器", "文件威胁分析", 
  "AI智能研判", "主机安全检测","情报管理"
];

const getMenuIcon = (index) => {
  const icons = ['📊', '🌐', '📁', '🤖', '🖥️'];
  return icons[index] || '📌';
};

const handleMenuClick = (index) => {
  currentMenuIndex.value = index;
};

const toggleNetworkMap = () => {
  showNetworkMap.value = !showNetworkMap.value;
};

const modules = [
  {
    title: '态势感知',
    component: SituationAwareness,
    buttons: [
      {
        id: 'network-map',
        icon: '🌍',
        text: '实时网络态势',
        action: toggleNetworkMap
      }
    ]
  },
  {
    title: '流量分析器',
    component: TrafficAnalyzer,
    buttons: [
      {
        id: 'export',
        icon: '📤',
        text: '导出数据'
      },
      {
        id: 'filter',
        icon: '🔍',
        text: '高级筛选'
      }
    ]
  },
  {
    title: '文件威胁分析',
    component: FileThreatAnalysis,
    buttons: [
      {
        id: 'history',
        icon: '📁',
        text: '历史文件',
        action: () => showHistoryDialog.value = true
      }
    ]
  },
  {
    title: 'AI智能研判',
    component: AIAnalysis,
    buttons: [
   
      {
        id: 'report',
        icon: '📊',
        text: '生成报告'
      }
    ]
  },
  {
    title: '主机安全检测',
    component: HostSecurity,
    buttons: [
      {
        id: 'agent',
        text: '下发Agent'
      }
    ]
  },
  {
    title: '情报管理中心',
    component: ThreatIntelligencer,
    
  },
];

const currentModule = computed(() => modules[currentMenuIndex.value]);

const handleButtonClick = (buttonId) => {
  const button = currentModule.value.buttons.find(b => b.id === buttonId);
  if (button && button.action) {
    button.action();
  }
};

const formatFileSize = (size) => {
  if (size < 1024) return size + ' B';
  if (size < 1024 * 1024) return (size / 1024).toFixed(2) + ' KB';
  return (size / (1024 * 1024)).toFixed(2) + ' MB';
};

const getThreatLevelType = (level) => {
  const types = {
    '高危': 'danger',
    '中危': 'warning',
    '低危': 'success'
  };
  return types[level] || 'info';
};

const formatDate = (dateStr) => {
  return new Date(dateStr).toLocaleString();
};

const fetchFileHistory = async () => {
  try {
    const response = await fetch('http://localhost:5000/api/file/history');
    const data = await response.json();
    fileHistory.value = data;
  } catch (error) {
    ElMessage.error('获取历史记录失败');
  }
};

const viewFileDetails = (file) => {
  // TODO: Implement file details view
  console.log('View file details:', file);
};

onMounted(() => {
  fetchFileHistory();
});
</script>

<style scoped>
.layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 240px;
  background: linear-gradient(180deg, #1a365d 0%, #2c5282 100%);
  color: white;
  height: 100vh;
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  box-shadow: 2px 0 8px rgba(0, 0, 0, 0.15);
}

.system-title {
  padding: 16px 20px;
  background: rgba(0, 0, 0, 0.2);
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.logo {
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo-icon {
  font-size: 24px;
}

.logo-text {
  font-size: 18px;
  font-weight: 520;
  color: white;
}

.nav-section {
  flex: 1;
  overflow-y: auto;
}

.nav-header {
  padding: 16px 20px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.nav-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.8);
}

.menu-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.menu-item {
  width: 100%;
  background-color: transparent;
  padding: 16px 20px;
  cursor: pointer;
  color: rgba(255, 255, 255, 0.65);
  border: none;
  text-align: left;
  transition: all 0.3s;
  font-size: 14px;
  position: relative;
  display: flex;
  align-items: center;
  gap: 12px;
}

.menu-item:hover {
  color: #fff;
  background-color: rgba(255, 255, 255, 0.1);
}

.menu-item.active {
  color: #fff;
  background-color: rgba(255, 255, 255, 0.15);
}

.menu-item.active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 4px;
  background-color: #1890ff;
}

.menu-icon {
  font-size: 18px;
}

.menu-text {
  flex: 1;
}

.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.content {
  flex: 1;
  padding: 24px;
  background-color: #f0f2f5;
  overflow-y: auto;
}

.content-header {
  margin-bottom: 24px;
  padding: 0 24px;
}

.header-left {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.content-header h2 {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  color: #1f1f1f;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  color: #666;
}

.breadcrumb .separator {
  color: #999;
}

.breadcrumb .current {
  color: #1890ff;
  font-weight: 500;
}

.content-body {
  background: white;
  padding: 24px;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  min-height: 200px;
  margin: 0 24px;
}

/* 自定义滚动条样式 */
.nav-section::-webkit-scrollbar {
  width: 6px;
}

.nav-section::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.1);
}

.nav-section::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 3px;
}

.nav-section::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}

@media screen and (max-width: 768px) {
  .sidebar {
    width: 100%;
    height: auto;
    position: fixed;
    top: 0;
    left: 0;
    z-index: 1000;
    transform: translateX(-100%);
    transition: transform 0.3s;
  }

  .sidebar.show {
    transform: translateX(0);
  }

  .system-title {
    padding: 12px 16px;
  }

  .logo-text {
    font-size: 16px;
  }

  .nav-header {
    padding: 12px 16px;
  }

  .menu-item {
    padding: 12px 16px;
  }

  .content {
    padding: 16px;
    margin-top: 60px;
  }
  
  .content-header {
    padding: 0 16px;
  }
  
  .content-body {
    margin: 0 16px;
    padding: 16px;
  }
}
</style>
