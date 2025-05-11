import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import eslint from 'vite-plugin-eslint'

export default defineConfig({
  plugins: [
    vue(),
    eslint({
      fix: true,
      include: ['src/**/*.vue', 'src/**/*.js']
    })
  ]
})