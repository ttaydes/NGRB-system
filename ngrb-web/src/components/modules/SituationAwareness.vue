<template>
  <div class="situation-awareness">
    <!-- 顶部统计卡片 -->
    <el-row :gutter="20" class="stat-cards">
      <el-col :span="6" v-for="(stat, index) in statistics" :key="index">
        <el-card shadow="hover" :body-style="{ padding: '20px' }">
          <div class="stat-item">
            <div class="stat-icon" :class="stat.type">
              <el-icon><component :is="stat.icon" /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ stat.value }}</div>
              <div class="stat-label">{{ stat.label }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 安全指数和告警分布 -->
    <el-row :gutter="20" class="chart-row">
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>安全指数趋势</span>
              <el-radio-group v-model="timeRange" size="small">
                <el-radio-button label="24">24小时</el-radio-button>
                <el-radio-button label="168">7天</el-radio-button>
                <el-radio-button label="720">30天</el-radio-button>
              </el-radio-group>
            </div>
          </template>
          <div ref="securityChartRef" class="chart-container"></div>
        </el-card>
      </el-col>
      <el-col :span="12" >
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>告警分布</span>
            </div>
          </template>
          <div class="alert-distribution">
            <div class="alert-buttons">
              <el-radio-group v-model="alertType" size="small">
                <el-radio-button label="traffic">流量分析</el-radio-button>
                <el-radio-button label="file">文件分析</el-radio-button>
                <el-radio-button label="host">主机分析</el-radio-button>
              </el-radio-group>
            </div>
            <div ref="alertChartRef" class="chart-container"></div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 威胁分析和分布地图 -->
    <el-row :gutter="20" class="chart-row">
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>威胁来源分布</span>
            </div>
          </template>
          <div ref="threatChartRef" class="chart-container"></div>
        </el-card>
      </el-col>
      
      <el-col :span="12">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>攻击分布地图</span>
            </div>
          </template>
          <div class="chart-container map-container">
            <v-chart class="chart" :option="attackTypeOption" :style="chartStyle" />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 实时告警和威胁词云 -->
    <el-row :gutter="20" class="chart-row">
      <el-col :span="16">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>实时告警</span>
              <el-button type="primary" size="small" @click="refreshAlerts">
                刷新
              </el-button>
            </div>
          </template>
          <div class="alert-carousel">
            <div class="alert-list" :style="{ transform: `translateY(${-currentIndex * 60}px)` }">
              <div v-for="(alert, index) in recentAlerts" 
                   :key="index" 
                   class="alert-item"
                   :class="{ 'alert-high': alert.risk_level === 'high', 
                            'alert-medium': alert.risk_level === 'medium',
                            'alert-low': alert.risk_level === 'low' }">
                <div class="alert-time">{{ formatTime(alert.timestamp) }}</div>
                <div class="alert-content">
                  <span class="alert-type">{{ alert.type }}</span>
                  <span class="alert-source">{{ alert.source }}</span>
                  <span class="alert-desc">{{ alert.description }}</span>
                </div>
                <el-tag :type="getRiskLevelType(alert.risk_level)" size="small">
                  {{ alert.risk_level }}
                </el-tag>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card class="chart-card">
          <template #header>
            <div class="card-header">
              <span>威胁词云</span>
            </div>
            <div class="chart-container">
            <div ref="wordCloudChart" style="width: 100%; height: 400px;"></div></div>
          </template>
         
        </el-card>
      </el-col>
    </el-row>

  </div>
</template>

<script>
import { ref, onMounted, computed, watch, onBeforeUnmount, nextTick } from 'vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, LineChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
} from 'echarts/components'
import VChart from 'vue-echarts'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import 'echarts-wordcloud'
import * as echarts from 'echarts'
import chinaMap from 'echarts/map/json/china.json'

// 注册必要的组件
use([
  CanvasRenderer,
  PieChart,
  LineChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
])

// 注册中国地图
echarts.registerMap('china', chinaMap)

const wordCloudChart = ref(null)
const wordCloudData = ref([])
let wordCloudInstance = null
let mapInstance = null

import {
  Warning,
  Connection,
  Monitor,
  Histogram
} from '@element-plus/icons-vue'

export default {
  name: 'SituationAwareness',
  components: {
    VChart,
    Warning,
    Connection,
    Monitor,
    Histogram
  },
  setup() {
    const timeRange = ref('24')
    const alertType = ref('traffic')
    const statistics = ref([
      { label: '安全指数', value: 0, icon: 'Monitor', type: 'primary' },
      { label: '告警总数', value: 0, icon: 'Warning', type: 'danger' },
      { label: '活跃主机', value: 0, icon: 'Connection', type: 'success' },
      { label: '威胁类型', value: 0, icon: 'Histogram', type: 'warning' }
    ])
    const recentAlerts = ref([])
    const securityData = ref({
      securityIndex: 0,
      alertStats: {
        traffic: { high: 0, medium: 0, low: 0 },
        file: { high: 0, medium: 0, low: 0 },
        host: { high: 0, medium: 0, low: 0 }
      },
      attackTypes: [],
      threatSources: [],
      trendTimes: [],
      trendValues: [],
      wordCloud: [],
      threatClassification: [],
      provinceThreats: []
    })

    const securityChartRef = ref(null)
    const alertChartRef = ref(null)
    const threatChartRef = ref(null)
    let securityChart = null
    let alertChart = null
    let threatChart = null

    const currentIndex = ref(0)
    let carouselTimer = null

    // 初始化安全指数趋势图
    const initSecurityChart = () => {
      if (securityChartRef.value) {
        securityChart = echarts.init(securityChartRef.value)
        updateSecurityChart()
      }
    }

    // 更新安全指数趋势图
    const updateSecurityChart = () => {
      if (!securityChart) return

      const option = {
        tooltip: {
          trigger: 'axis',
          formatter: function(params) {
            const data = params[0]
            return `${data.name}<br/>安全指数: ${data.value}`
          }
        },
        grid: {
          left: '3%',
          right: '4%',
          bottom: '3%',
          containLabel: true
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: securityData.value.trendTimes,
          axisLabel: {
            rotate: 45,
            formatter: function(value) {
              // 只显示日期和小时
              return value.split(' ')[1]
            }
          }
        },
        yAxis: {
          type: 'value',
          min: 0,
          max: 100,
          name: '安全指数',
          nameTextStyle: {
            padding: [0, 0, 0, 40]
          },
          splitLine: {
            lineStyle: {
              type: 'dashed'
            }
          }
        },
        series: [{
          name: '安全指数',
          type: 'line',
          smooth: true,
          symbol: 'circle',
          symbolSize: 8,
          data: securityData.value.trendValues,
          areaStyle: {
            opacity: 0.3,
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(64, 158, 255, 0.5)' },
              { offset: 1, color: 'rgba(64, 158, 255, 0.1)' }
            ])
          },
          itemStyle: {
            color: '#409EFF'
          },
          lineStyle: {
            width: 3
          },
          emphasis: {
            focus: 'series',
            itemStyle: {
              borderWidth: 2
            }
          }
        }]
      }

      securityChart.setOption(option)
    }

    // 初始化告警分布图表
    const initAlertChart = () => {
      if (alertChartRef.value) {
        alertChart = echarts.init(alertChartRef.value)
        updateAlertChart()
      }
    }

    // 更新告警分布图表
    const updateAlertChart = () => {
      if (!alertChart) return

      const data = securityData.value.alertStats[alertType.value] || {
        high: 0,
        medium: 0,
        low: 0
      }

      const option = {
        tooltip: {
          trigger: 'item',
          formatter: '{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'vertical',
          right: 10,
          top: 'center'
        },
        series: [{
          name: '告警分布',
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['40%', '50%'],
          avoidLabelOverlap: true,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#fff',
            borderWidth: 2
          },
          label: {
            show: true,
            formatter: '{b}\n{d}%'
          },
          emphasis: {
            label: {
              show: true,
              fontSize: '14',
              fontWeight: 'bold'
            }
          },
          data: [
            { value: data.high, name: '高风险', itemStyle: { color: '#F56C6C' } },
            { value: data.medium, name: '中风险', itemStyle: { color: '#E6A23C' } },
            { value: data.low, name: '低风险', itemStyle: { color: '#67C23A' } }
          ]
        }]
      }

      alertChart.setOption(option)
    }

    // 初始化威胁来源分布图表
    const initThreatChart = () => {
      if (threatChartRef.value) {
        threatChart = echarts.init(threatChartRef.value)
        updateThreatChart()
      }
    }

    // 更新威胁来源分布图表
    const updateThreatChart = () => {
      if (!threatChart) return

      const threatData = securityData.value.threatSources || []

      const option = {
        tooltip: {
          trigger: 'item',
          formatter: '{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'vertical',
          right: 10,
          top: 'center',
          type: 'scroll'
        },
        series: [{
          name: '威胁来源',
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['40%', '50%'],
          avoidLabelOverlap: true,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#fff',
            borderWidth: 2
          },
          label: {
            show: true,
            formatter: '{b}\n{d}%'
          },
          emphasis: {
            label: {
              show: true,
              fontSize: '14',
              fontWeight: 'bold'
            }
          },
          data: threatData.map(item => ({
            name: item.name,
            value: item.value
          }))
        }]
      }

      threatChart.setOption(option)
    }

    // 修改攻击类型分布为地图配置
    const attackTypeOption = computed(() => ({
      tooltip: {
        trigger: 'item',
        formatter: function(params) {
          if (params.data) {
            return `${params.name}<br/>威胁数量: ${params.value}`
          }
          return params.name
        }
      },
      visualMap: {
        min: 0,
        max: 300,
        left: 'left',
        top: 'bottom',
        text: ['高', '低'],
        calculable: true,
        inRange: {
          color: ['#e0f3f8', '#045a8d']
        }
      },
      geo: {
        map: 'china',
        roam: true,
        emphasis: {
          label: {
            show: true
          }
        }
      },
      series: [{
        name: '威胁分布',
        type: 'map',
        map: 'china',
        roam: true,
        emphasis: {
          label: {
            show: true
          }
        },
        data: securityData.value.provinceThreats || []
      }]
    }))

    // 修改词云图配置
    // 渲染词云图表
const renderWordCloud = () => {
  if (!wordCloudChart.value) return

  // 初始化图表
  if (!wordCloudInstance) {
    wordCloudInstance = echarts.init(wordCloudChart.value)
  }

  const option = {
    tooltip: {
      show: true,
      formatter: (params) => `${params.name}: ${params.value}`
    },
    series: [
      {
        type: 'wordCloud',
        shape: 'circle',
        gridSize: 8,
        sizeRange: [12, 60],
        rotationRange: [-90, 90],
        textStyle: {
          normal: {
            color: () => {
              return (
                'rgb(' +
                [
                  Math.round(Math.random() * 160),
                  Math.round(Math.random() * 160),
                  Math.round(Math.random() * 160)
                ].join(',') +
                ')'
              )
            }
          },
          emphasis: {
            shadowBlur: 10,
            shadowColor: '#333'
          }
        },
        data: wordCloudData.value
      }
    ]
  }

  wordCloudInstance.setOption(option)
}

    // 获取安全态势数据
    const fetchSecurityData = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/situation/overview?timeRange=' + timeRange.value)
        securityData.value = response.data
        
        // 更新所有图表
        updateSecurityChart()
        updateAlertChart()
        updateThreatChart()
        
        // 更新统计卡片数据
        statistics.value[0].value = securityData.value.securityIndex
        statistics.value[1].value = 
          securityData.value.alertStats.traffic.high + 
          securityData.value.alertStats.traffic.medium + 
          securityData.value.alertStats.traffic.low +
          securityData.value.alertStats.file.high +
          securityData.value.alertStats.file.medium +
          securityData.value.alertStats.file.low +
          securityData.value.alertStats.host.high +
          securityData.value.alertStats.host.medium +
          securityData.value.alertStats.host.low
        statistics.value[2].value = securityData.value.activeHosts
        statistics.value[3].value = securityData.value.threatSources?.length || 0

        // 更新词云数据
        wordCloudData.value = securityData.value.wordCloud
        renderWordCloud()

        // 更新地图数据
        if (mapInstance) {
          mapInstance.setOption(attackTypeOption.value)
        }
      } catch (error) {
        console.error('获取安全态势数据失败:', error)
        ElMessage.error('获取安全态势数据失败')
      }
    }

    // 开始轮播
    const startCarousel = () => {
      if (carouselTimer) {
        clearInterval(carouselTimer)
      }
      carouselTimer = setInterval(() => {
        if (recentAlerts.value.length > 0) {
          currentIndex.value = (currentIndex.value + 1) % recentAlerts.value.length
        }
      }, 3000) // 每3秒切换一次
    }

    // 获取最近告警
    const fetchRecentAlerts = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/situation/alerts')
        recentAlerts.value = response.data
        currentIndex.value = 0
        startCarousel()
      } catch (error) {
        ElMessage.error('获取告警数据失败')
      }
    }

    // 刷新告警数据
    const refreshAlerts = () => {
      fetchRecentAlerts()
    }

    // 格式化时间
    const formatTime = (timestamp) => {
      return new Date(timestamp).toLocaleString()
    }

    // 获取风险等级对应的标签类型
    const getRiskLevelType = (level) => {
      const types = {
        high: 'danger',
        medium: 'warning',
        low: 'info'
      }
      return types[level] || 'info'
    }

    // 监听时间范围变化
    watch(timeRange, () => {
      fetchSecurityData()
      // 重新初始化图表以确保正确显示
      nextTick(() => {
        if (securityChart) {
          securityChart.resize()
        }
      })
    })

    // 监听告警类型变化
    watch(alertType, () => {
      fetchSecurityData()
    })

    onMounted(() => {
      initSecurityChart()
      initAlertChart()
      initThreatChart()
      fetchSecurityData()
      fetchRecentAlerts()
      
      // 初始化地图
      const mapChart = document.querySelector('.map-container')
      if (mapChart) {
        mapInstance = echarts.init(mapChart)
        mapInstance.setOption(attackTypeOption.value)
      }

      // 定时刷新数据
      setInterval(() => {
        fetchSecurityData()
        fetchRecentAlerts()
      }, 60000) // 每分钟刷新一次

      // 监听窗口大小变化
      window.addEventListener('resize', () => {
        securityChart?.resize()
        alertChart?.resize()
        threatChart?.resize()
        mapInstance?.resize()
      })
    })

    onBeforeUnmount(() => {
      if (wordCloudInstance) {
        wordCloudInstance.dispose()
      }
      if (mapInstance) {
        mapInstance.dispose()
      }
      securityChart?.dispose()
      alertChart?.dispose()
      threatChart?.dispose()
      window.removeEventListener('resize', () => {
        securityChart?.resize()
        alertChart?.resize()
        threatChart?.resize()
        mapInstance?.resize()
      })
      if (carouselTimer) {
        clearInterval(carouselTimer)
      }
    })

    // 修改图表容器样式
    const chartStyle = {
      height: '100%',
      width: '100%'
    }

    return {
      securityChartRef,
      alertChartRef,
      threatChartRef,
      timeRange,
      alertType,
      statistics,
      recentAlerts,
      refreshAlerts,
      formatTime,
      wordCloudChart,
      getRiskLevelType,
      chartStyle,
      currentIndex
    }
  }
}
</script>

<style scoped>
.situation-awareness {
  padding: 20px;
}

.stat-cards {
  margin-bottom: 20px;
}

.stat-item {
  display: flex;
  align-items: center;
}

.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 12px;
}

.stat-icon.primary {
  background-color: #409eff;
  color: white;
}

.stat-icon.danger {
  background-color: #f56c6c;
  color: white;
}

.stat-icon.success {
  background-color: #67c23a;
  color: white;
}

.stat-icon.warning {
  background-color: #e6a23c;
  color: white;
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  line-height: 1;
  margin-bottom: 8px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
}

.chart-row {
  margin-bottom: 20px;
}

.chart-card {
  height: 100%;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
}

.chart-container {
  height: 300px;
  width: 100%;
  position: relative;
}

:deep(.el-card__header) {
  padding: 15px 20px;
  border-bottom: 1px solid #ebeef5;
  box-sizing: border-box;
}

.alert-distribution {
  display: flex;
  height: 100%;
}

.alert-buttons {
  padding: 10px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  border-right: 1px solid #EBEEF5;
  background-color: #f5f7fa;
}

.alert-buttons :deep(.el-radio-group) {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.alert-buttons :deep(.el-radio-button) {
  margin: 0;
}

.alert-buttons :deep(.el-radio-button__inner) {
  width: 80px;
  text-align: center;
  border: none;
  background: transparent;
  color: #606266;
  padding: 8px 12px;
}

.alert-buttons :deep(.el-radio-button__original-radio:checked + .el-radio-button__inner) {
  color: #409EFF;
  background: #ecf5ff;
  box-shadow: none;
  border: none;
}

:deep(.echarts) {
  width: 100%;
  height: 100%;
}

.alert-carousel {
  height: 300px;
  overflow: hidden;
  position: relative;
  background: #f5f7fa;
  border-radius: 4px;
}

.alert-list {
  transition: transform 0.5s ease-in-out;
}

.alert-item {
  height: 60px;
  padding: 10px 15px;
  display: flex;
  align-items: center;
  background: white;
  margin: 5px;
  border-radius: 4px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  transition: all 0.3s ease;
}

.alert-item:hover {
  transform: translateX(5px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.alert-time {
  width: 150px;
  color: #909399;
  font-size: 12px;
}

.alert-content {
  flex: 1;
  margin: 0 15px;
  display: flex;
  align-items: center;
  gap: 15px;
}

.alert-type {
  color: #409EFF;
  font-weight: bold;
  min-width: 80px;
}

.alert-source {
  color: #606266;
  min-width: 120px;
}

.alert-desc {
  color: #606266;
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.alert-high {
  border-left: 4px solid #F56C6C;
}

.alert-medium {
  border-left: 4px solid #E6A23C;
}

.alert-low {
  border-left: 4px solid #67C23A;
}

:deep(.el-tag) {
  min-width: 60px;
  text-align: center;
}
</style>