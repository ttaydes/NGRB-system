<template>
  <header class="header">
    <div class="header-left">
      <div class="module-buttons" v-if="buttons && buttons.length">
        <button 
          v-for="button in buttons" 
          :key="button.id"
          class="btn"
          @click="handleButtonClick(button.id)"
        >
          {{ button.text }}
        </button>
      </div>
     
    </div>
    <div class="header-right">
      <div class="user-info">
        <span class="user-avatar">👤</span>
        <span class="user-name">管理员</span>
      </div>
      <div class="system-info">
        <span class="time">{{ currentTime }}</span>
        <span class="status online">系统运行正常</span>
      </div>
    </div>
  </header>
</template>

<script>
export default {
  name: 'HeaderBar',
  props: {
    buttons: {
      type: Array,
      default: () => []
    }
  },
  data() {
    return {
      currentTime: ''
    }
  },
  methods: {
    updateTime() {
      const now = new Date();
      this.currentTime = now.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    },
    handleButtonClick(buttonId) {
      this.$emit('button-click', buttonId);
    }
  },
  mounted() {
    this.updateTime();
    this.timer = setInterval(this.updateTime, 1000);
  },
  beforeUnmount() {
    if (this.timer) {
      clearInterval(this.timer);
    }
  }
}
</script>

<style scoped>
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
  color: white;
  padding: 0 24px;
  height: 60px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
}

.header-left {
  display: flex;
  align-items: center;
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
  font-size: 20px;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 24px;
}

.module-buttons {
  display: flex;
  gap: 12px;
}

.btn {
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

.btn.active {
  color: #fff;
  background-color: rgba(255, 255, 255, 0.15);
}

.btn:hover {
  color: #fff;
  background-color: rgba(255, 255, 255, 0.1);
}



.user-info {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 20px;
  transition: background-color 0.3s;
}

.user-info:hover {
  background: rgba(255, 255, 255, 0.2);
}

.user-avatar {
  font-size: 20px;
}

.user-name {
  font-size: 14px;
  font-weight: 500;
}

.system-info {
  display: flex;
  align-items: center;
  gap: 16px;
}

.time {
  font-size: 14px;
  color: rgba(255, 255, 255, 0.8);
}

.status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  padding: 4px 12px;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.1);
}

.status.online {
  color: #52c41a;
}

.status.online::before {
  content: '';
  display: inline-block;
  width: 6px;
  height: 6px;
  background: #52c41a;
  border-radius: 50%;
}

@media screen and (max-width: 768px) {
  .header {
    padding: 0 16px;
  }
  
  .logo-text {
    font-size: 16px;
  }
  
  .system-info {
    display: none;
  }

  .module-buttons {
    flex-direction: column;
    gap: 8px;
  }

  .btn {
    width: 100%;
    justify-content: center;
  }
}
</style>