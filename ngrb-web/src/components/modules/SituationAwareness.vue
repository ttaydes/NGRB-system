<template>
  <div class="situation-awareness">
    <!-- 总体安全态势指标 -->
    <div class="security-index">
      <div class="gauge-chart" ref="gaugeChart"></div>
      <div class="index-text">
        <h3>当前安全态势总览</h3>
        <div class="index-value">{{ securityIndex }}%</div>
      </div>
    </div>

    <!-- 3D地球和攻击路线 -->
    <div class="earth-container" ref="earthContainer"></div>

    <!-- 数据统计面板 -->
    <div class="stats-panel">
      <!-- 告警统计 -->
      <el-card class="stats-card">
        <template #header>
          <div class="card-header">
            <span style="color: red;">告警统计</span>
            <el-tag type="danger" v-if="hasNewAlert">新告警</el-tag>
          </div>
        </template>
        <div class="alert-stats">
          <div class="alert-chart" ref="alertChart"></div>
          <div class="alert-list">
            <div v-for="alert in recentAlerts" :key="alert.id" class="alert-item" :class="alert.level">
              <el-icon><Warning /></el-icon>
              <span>{{ alert.message }}</span>
              <span class="alert-time">{{ alert.time }}</span>
            </div>
          </div>
        </div>
      </el-card>

      <!-- 攻击类型分布 -->
      <el-card class="stats-card">
        <template #header>
          <div class="card-header">
            <span style="color: red;">攻击类型分布</span>
          </div>
        </template>
        <div class="attack-chart" ref="attackChart"></div>
      </el-card>

      <!-- 实时攻击态势 -->
      <el-card class="stats-card">
        <template #header>
          <div class="card-header">
            <span style="color: red">实时攻击态势</span>
          </div>
        </template>
        <div class="realtime-attacks">
          <div class="attack-timeline" ref="timelineChart"></div>
          <div class="attack-status">
            <div class="status-item">
              <div class="status-label">可疑</div>
              <div class="status-value">{{ attackStats.suspicious }}</div>
            </div>
            <div class="status-item">
              <div class="status-label">攻击成功</div>
              <div class="status-value success">{{ attackStats.success }}</div>
            </div>
            <div class="status-item">
              <div class="status-label">攻击失败</div>
              <div class="status-value failed">{{ attackStats.failed }}</div>
            </div>
          </div>
        </div>
      </el-card>
    </div>

    <!-- 访问者地域分布 -->
    <div class="visitor-distribution">
      <div class="distribution-chart" ref="distributionChart"></div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';
import * as TWEEN from '@tweenjs/tween.js';
import echarts from 'echarts';
// 引入中国地图
import 'echarts/map/js/china';
import { Warning } from '@element-plus/icons-vue';
import io from 'socket.io-client';

export default {
  name: 'SituationAwareness',
  components: {
    Warning
  },
  setup() {
    // 引用
    const earthContainer = ref(null);
    const gaugeChart = ref(null);
    const alertChart = ref(null);
    const attackChart = ref(null);
    const timelineChart = ref(null);
    const distributionChart = ref(null);

    // 数据
    const securityIndex = ref(46);
    const hasNewAlert = ref(false);
    const recentAlerts = ref([]);
    const attackStats = ref({
      suspicious: 55,
      success: 94,
      failed: 23
    });

    // Three.js 相关变量
    let scene, camera, renderer, earth, controls;
    let attackLines = [];
    let charts = {};

    // 初始化3D地球
    const initEarth = () => {
      if (!earthContainer.value) return;
      
      scene = new THREE.Scene();
      camera = new THREE.PerspectiveCamera(75, earthContainer.value.clientWidth / earthContainer.value.clientHeight, 0.1, 1000);
      
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      renderer.setSize(earthContainer.value.clientWidth, earthContainer.value.clientHeight);
      earthContainer.value.appendChild(renderer.domElement);

      // 创建地球
      const geometry = new THREE.SphereGeometry(5, 32, 32);
      const textureLoader = new THREE.TextureLoader();
      const material = new THREE.MeshPhongMaterial({
        map: textureLoader.load('/img/earth-bump.jpg'),
        bumpMap: textureLoader.load('/img/earth-texture.jpg'),
        bumpScale: 0.05,
        specularMap: textureLoader.load('/img/earth-texture.jpg'),
        specular: new THREE.Color('grey')
      });
      
      earth = new THREE.Mesh(geometry, material);
      scene.add(earth);

      // 添加环境光和平行光
      const ambientLight = new THREE.AmbientLight(0x333333);
      scene.add(ambientLight);
      
      const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
      directionalLight.position.set(5, 3, 5);
      scene.add(directionalLight);

      camera.position.z = 15;

      // 添加控制器
      controls = new OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.05;
      controls.rotateSpeed = 0.5;

      animate();
    };

    // 动画循环
    const animate = () => {
      if (!earth || !scene || !camera || !renderer) return;
      
      requestAnimationFrame(animate);
      TWEEN.update();
      earth.rotation.y += 0.001;
      controls.update();
      renderer.render(scene, camera);
    };

    // 初始化仪表盘
    const initGaugeChart = () => {
      if (!gaugeChart.value) return;
      
      const chart = echarts.init(gaugeChart.value);
      charts.gauge = chart;
      
      const option = {
        series: [{
          type: 'gauge',
          min: 0,
          max: 100,
          splitNumber: 10,
          radius: '90%',
          axisLine: {
            lineStyle: {
              color: [
                [0.2, '#ff4500'],
                [0.4, '#ff7800'],
                [0.6, '#ffd700'],
                [0.8, '#9acd32'],
                [1, '#32cd32']
              ],
              width: 20
            }
          },
          axisTick: {
            length: 12,
            lineStyle: {
              color: 'auto'
            }
          },
          splitLine: {
            length: 20,
            lineStyle: {
              color: 'auto'
            }
          },
          pointer: {
            width: 5
          },
          title: {
            offsetCenter: [0, '80%'],
            textStyle: {
              color: '#fff',
              fontSize: 15
            }
          },
          detail: {
            formatter: '{value}%',
            textStyle: {
              color: '#fff',
              fontSize: 25
            }
          },
          data: [{
            value: securityIndex.value,
            name: '安全指数'
          }]
        }]
      };
      chart.setOption(option);
    };

    // 初始化告警统计图
    const initAlertChart = () => {
      if (!alertChart.value) return;
      
      const chart = echarts.init(alertChart.value);
      charts.alert = chart;
      
      const option = {
        tooltip: {
          trigger: 'item',
          formatter: '{a} <br/>{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'horizontal',
          bottom: 10,
          textStyle: {
            color: '#fff'
          },
          data: ['低危', '中危', '高危']
        },
        color: ['#91cc75', '#fac858', '#ee6666'],
        series: [
          {
            name: '告警级别',
            type: 'pie',
            radius: ['50%', '70%'],
            avoidLabelOverlap: false,
            label: {
              show: false
            },
            emphasis: {
              label: {
                show: true,
                fontSize: '20',
                fontWeight: 'bold'
              }
            },
            labelLine: {
              show: false
            },
            data: [
              { value: 40, name: '低危' },
              { value: 35, name: '中危' },
              { value: 25, name: '高危' }
            ]
          }
        ]
      };
      chart.setOption(option);
    };

    // 初始化攻击类型分布图
    const initAttackChart = () => {
      if (!attackChart.value) return;
      
      const chart = echarts.init(attackChart.value);
      charts.attack = chart;
      
      const option = {
        tooltip: {
          trigger: 'item',
          formatter: '{a} <br/>{b}: {c} ({d}%)'
        },
        legend: {
          orient: 'vertical',
          right: 10,
          top: 'center',
          textStyle: {
            color: '#fff'
          }
        },
        series: [
          {
            name: '攻击类型',
            type: 'pie',
            radius: ['50%', '70%'],
            center: ['40%', '50%'],
            avoidLabelOverlap: false,
            label: {
              show: false
            },
            emphasis: {
              label: {
                show: true,
                fontSize: '20',
                fontWeight: 'bold'
              }
            },
            labelLine: {
              show: false
            },
            data: [
              { value: 335, name: 'SQL注入' },
              { value: 310, name: 'XSS攻击' },
              { value: 234, name: '暴力破解' },
              { value: 135, name: 'Web漏洞' },
              { value: 148, name: '其他' }
            ]
          }
        ]
      };
      chart.setOption(option);
    };

    // 初始化时间线图表
    const initTimelineChart = () => {
      if (!timelineChart.value) return;
      
      const chart = echarts.init(timelineChart.value);
      charts.timeline = chart;
      
      const option = {
        tooltip: {
          trigger: 'axis',
          axisPointer: {
            type: 'shadow'
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
          data: ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'],
          axisLabel: {
            color: '#fff'
          },
          axisLine: {
            lineStyle: {
              color: '#fff'
            }
          }
        },
        yAxis: {
          type: 'value',
          axisLabel: {
            color: '#fff'
          },
          axisLine: {
            lineStyle: {
              color: '#fff'
            }
          },
          splitLine: {
            lineStyle: {
              color: 'rgba(255,255,255,0.1)'
            }
          }
        },
        series: [
          {
            name: '攻击次数',
            type: 'line',
            smooth: true,
            symbol: 'none',
            sampling: 'average',
            itemStyle: {
              color: '#508dff'
            },
            areaStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: 'rgba(80,141,255,0.5)' },
                { offset: 1, color: 'rgba(80,141,255,0.1)' }
              ])
            },
            data: [120, 132, 101, 134, 90, 230, 210, 182]
          }
        ]
      };
      chart.setOption(option);
    };

    // 初始化访问地域分布图
    const initDistributionChart = () => {
      if (!distributionChart.value) return;
      
      const chart = echarts.init(distributionChart.value);
      charts.distribution = chart;
      
      const option = {
        title: {
          text: '访问地域分布',
          left: 'center',
          textStyle: {
            color: '#fff'
          }
        },
        tooltip: {
          trigger: 'item'
        },
        visualMap: {
          min: 0,
          max: 200,
          left: 'left',
          top: 'bottom',
          text: ['高', '低'],
          calculable: true,
          inRange: {
            color: ['#50a3ba', '#eac736', '#d94e5d']
          },
          textStyle: {
            color: '#fff'
          }
        },
        series: [
          {
            name: '访问量',
            type: 'map',
            map: 'china',
            roam: true,
            emphasis: {
              label: {
                show: true
              }
            },
            itemStyle: {
              areaColor: '#323c48',
              borderColor: '#fff'
            },
            data: [
              { name: '北京', value: 200 },
              { name: '上海', value: 180 },
              { name: '广东', value: 150 }
            ]
          }
        ]
      };
      chart.setOption(option);
    };

    // WebSocket连接
    let socket;
    const initWebSocket = () => {
      socket = io('http://localhost:5000');
      
      socket.on('security_update', (data) => {
        securityIndex.value = data.index;
        updateCharts(data);
      });

      socket.on('attack_alert', (data) => {
        hasNewAlert.value = true;
        recentAlerts.value.unshift(data);
        if (recentAlerts.value.length > 5) {
          recentAlerts.value.pop();
        }
        if (data.source && data.target) {
          addAttackLine(data.source, data.target);
        }
      });
    };

    // 更新图表数据
    const updateCharts = (data) => {
      // 更新仪表盘
      if (data.index !== undefined && charts.gauge) {
        charts.gauge.setOption({
          series: [{
            data: [{
              value: data.index,
              name: '安全指数'
            }]
          }]
        });
      }

      // 更新告警统计
      if (data.alerts && charts.alert) {
        charts.alert.setOption({
          series: [{
            data: [
              { value: data.alerts.low, name: '低危' },
              { value: data.alerts.medium, name: '中危' },
              { value: data.alerts.high, name: '高危' }
            ]
          }]
        });
      }

      // 更新攻击类型分布
      if (data.attackTypes && charts.attack) {
        charts.attack.setOption({
          series: [{
            data: Object.entries(data.attackTypes).map(([name, value]) => ({
              name,
              value
            }))
          }]
        });
      }

      // 更新时间线
      if (data.timeline && charts.timeline) {
        charts.timeline.setOption({
          xAxis: {
            data: data.timeline.times
          },
          series: [{
            data: data.timeline.values
          }]
        });
      }

      // 更新攻击状态统计
      if (data.attackStats) {
        attackStats.value = data.attackStats;
      }
    };

    // 添加攻击线条
    const addAttackLine = (source, target) => {
      if (!scene || !earth) return;
      
      // 将经纬度转换为3D坐标
      const sourcePos = latLongToVector3(source.lat, source.lng);
      const targetPos = latLongToVector3(target.lat, target.lng);

      const curve = new THREE.QuadraticBezierCurve3(
        sourcePos,
        sourcePos.clone().add(targetPos).multiplyScalar(0.5).normalize().multiplyScalar(7),
        targetPos
      );

      const points = curve.getPoints(50);
      const geometry = new THREE.BufferGeometry().setFromPoints(points);
      const material = new THREE.LineBasicMaterial({
        color: 0xff0000,
        transparent: true,
        opacity: 0.8,
        linewidth: 2
      });

      const line = new THREE.Line(geometry, material);
      scene.add(line);
      attackLines.push(line);

      // 动画效果
      new TWEEN.Tween({ opacity: 0 })
        .to({ opacity: 0.8 }, 1000)
        .onUpdate(function(obj) {
          material.opacity = obj.opacity;
        })
        .start();

      // 自动移除旧的攻击线
      setTimeout(() => {
        new TWEEN.Tween({ opacity: material.opacity })
          .to({ opacity: 0 }, 1000)
          .onUpdate(function(obj) {
            material.opacity = obj.opacity;
          })
          .onComplete(function() {
            scene.remove(line);
            const index = attackLines.indexOf(line);
            if (index > -1) {
              attackLines.splice(index, 1);
            }
          })
          .start();
      }, 4000);
    };

    // 经纬度转换为3D坐标
    const latLongToVector3 = (lat, long) => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (long + 180) * (Math.PI / 180);
      const radius = 5;

      return new THREE.Vector3(
        -radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta)
      );
    };

    // 生命周期钩子
    onMounted(() => {
      // 延迟初始化以确保DOM已经渲染
      setTimeout(() => {
        initEarth();
        initGaugeChart();
        initAlertChart();
        initAttackChart();
        initTimelineChart();
        initDistributionChart();
        initWebSocket();
      }, 100);

      window.addEventListener('resize', onResize);
    });

    onUnmounted(() => {
      window.removeEventListener('resize', onResize);
      if (socket) {
        socket.disconnect();
      }
      // 清理Three.js资源
      if (renderer) {
        renderer.dispose();
      }
      if (controls) {
        controls.dispose();
      }
      // 清理ECharts实例
      Object.values(charts).forEach(chart => {
        chart.dispose();
      });
    });

    // 窗口大小改变处理
    const onResize = () => {
      if (camera && renderer && earthContainer.value) {
        camera.aspect = earthContainer.value.clientWidth / earthContainer.value.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(earthContainer.value.clientWidth, earthContainer.value.clientHeight);
      }
      // 重置所有图表大小
      Object.values(charts).forEach(chart => {
        chart.resize();
      });
    };

    return {
      earthContainer,
      gaugeChart,
      alertChart,
      attackChart,
      timelineChart,
      distributionChart,
      securityIndex,
      hasNewAlert,
      recentAlerts,
      attackStats
    };
  }
};
</script>

<style scoped>
.situation-awareness {
  width: 98%;
  height: 100vh;
  background-color: #1a1a1a;
  color: #fff;
  display: grid;
  grid-template-columns: 300px 1fr 300px;
  grid-template-rows: auto 1fr auto;
  gap: 20px;
  padding: 20px;
  overflow: hidden;
}

.security-index {
  grid-column: 1;
  grid-row: 1;
  background: rgba(0, 0, 0, 0.5);
  border-radius: 10px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  align-items: center;
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

.gauge-chart {
  width: 100%;
  height: 300px;
}

.earth-container {
  grid-column: 2;
  grid-row: 1 / span 3;
  width: 100%;
  height: 100%;
  position: relative;
  overflow: hidden;
  border-radius: 10px;
  background: rgba(0, 0, 0, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

.stats-panel {
  grid-column: 3;
  grid-row: 1 / span 2;
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-height: 100%;
  overflow-y: auto;
}

.stats-card {
  background: rgba(0, 0, 0, 0.5) !important;
  border: 1px solid rgba(255, 255, 255, 0.1) !important;
  border-radius: 10px;
  backdrop-filter: blur(10px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.alert-stats {
  height: 300px;
  padding: 20px;
}

.alert-chart {
  height: 200px;
}

.alert-list {
  margin-top: 10px;
  max-height: 200px;
  overflow-y: auto;
}

.alert-item {
  display: flex;
  align-items: center;
  padding: 10px;
  margin-bottom: 5px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.05);
  transition: all 0.3s ease;
}

.alert-item:hover {
  background: rgba(255, 255, 255, 0.1);
}

.alert-item.high {
  border-left: 4px solid #ee6666;
}

.alert-item.medium {
  border-left: 4px solid #fac858;
}

.alert-item.low {
  border-left: 4px solid #91cc75;
}

.alert-time {
  margin-left: auto;
  font-size: 0.8em;
  color: #888;
}

.attack-chart {
  height: 300px;
  padding: 20px;
}

.realtime-attacks {
  height: 400px;
  padding: 20px;
}

.attack-status {
  display: flex;
  justify-content: space-around;
  margin-top: 20px;
}

.status-item {
  text-align: center;
  padding: 15px;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 8px;
  transition: all 0.3s ease;
}

.status-item:hover {
  background: rgba(255, 255, 255, 0.1);
  transform: translateY(-2px);
}

.status-label {
  font-size: 14px;
  color: #888;
}

.status-value {
  font-size: 24px;
  font-weight: bold;
  margin-top: 5px;
}

.status-value.success {
  color: #91cc75;
}

.status-value.failed {
  color: #ee6666;
}

.visitor-distribution {
  grid-column: 1;
  grid-row: 2 / span 2;
  background: rgba(0, 0, 0, 0.5);
  border-radius: 10px;
  padding: 20px;
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

.distribution-chart {
  width: 100%;
  height: 400px;
}

/* 自定义滚动条样式 */
::-webkit-scrollbar {
  width: 6px;
}

::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 3px;
}

::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.3);
  border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.5);
}

/* Element Plus 组件暗色主题适配 */
:deep(.el-card) {
  --el-card-bg-color: transparent !important;
  --el-card-border-color: rgba(255, 255, 255, 0.1) !important;
}

:deep(.el-tag) {
  background-color: rgba(255, 255, 255, 0.1);
  border: none;
}
</style>