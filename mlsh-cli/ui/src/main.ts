import { createApp } from 'vue'
import { router } from './router'
import App from './App.vue'
import './assets/styles/base.css'
import './composables/useTheme'

const app = createApp(App).use(router)
router.isReady().then(() => app.mount('#app'))
