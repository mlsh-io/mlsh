import { createApp } from 'vue'
import { router } from './router'
import App from './App.vue'
import './assets/styles/base.css'
import './composables/useTheme'

createApp(App).use(router).mount('#app')
