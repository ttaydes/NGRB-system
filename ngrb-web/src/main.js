import { createApp } from 'vue'
import App from './App.vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'

const app = createApp(App)

// 注册所有图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

app.use(ElementPlus)
app.mount('#app')

// 添加以下代码来处理 ResizeObserver 警告
const debounce = (fn, delay) => {
  let timeoutId
  return (...args) => {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => fn.apply(this, args), delay)
  }
}

window.addEventListener('load', () => {
  const resizeObserverError = debounce(() => {
    // ResizeObserver 错误处理
    const resizeObserverErr = document.getElementById('webpack-dev-server-client-overlay')
    if (resizeObserverErr) {
      resizeObserverErr.style.display = 'none'
    }
  }, 100)

  window.addEventListener('error', (e) => {
    if (e.message === 'ResizeObserver loop completed with undelivered notifications.') {
      resizeObserverError()
    }
  })
})
