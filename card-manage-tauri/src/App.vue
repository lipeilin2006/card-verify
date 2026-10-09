<script setup>
import { onMounted, ref } from "vue";
import { Tickets, Setting } from "@element-plus/icons-vue";
import { configReady, loadConfig } from "./api";

const ready = ref(false);

onMounted(() => {
  loadConfig();
  ready.value = true;
});
</script>

<template>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <p class="eyebrow">CARD CONTROL</p>
        <h1>卡密管理</h1>
      </div>
      <el-tag :type="configReady ? 'success' : 'warning'" effect="plain" size="large">
        {{ configReady ? "已配置" : "未配置" }}
      </el-tag>
    </header>

    <nav class="tabbar">
      <router-link to="/" class="tab-item" :class="{ active: $route.path === '/' }">
        <el-icon :size="20"><Tickets /></el-icon>
        <span>卡密管理</span>
      </router-link>
      <router-link to="/config" class="tab-item" :class="{ active: $route.path === '/config' }">
        <el-icon :size="20"><Setting /></el-icon>
        <span>连接配置</span>
      </router-link>
    </nav>

    <router-view v-if="ready" />
  </main>
</template>

<style>
:root { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17232e; background: #edf3f1; font-synthesis: none; text-rendering: optimizeLegibility; -webkit-tap-highlight-color: transparent; }
* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; }
.shell { width: min(760px, 100%); margin: 0 auto; padding: max(14px, env(safe-area-inset-top)) 14px calc(88px + env(safe-area-inset-bottom)); }
.topbar { display: flex; justify-content: space-between; align-items: center; padding: 8px 4px 12px; }
.eyebrow { margin: 0 0 3px; color: #628478; font-size: 11px; font-weight: 800; letter-spacing: .18em; }
h1 { margin: 0; font-size: clamp(24px, 7vw, 34px); letter-spacing: -.05em; }

.tabbar { position: fixed; left: 0; right: 0; bottom: 0; z-index: 200; display: flex; gap: 8px; padding: 8px 16px calc(8px + env(safe-area-inset-bottom)); background: rgba(255, 255, 255, .94); border-top: 1px solid rgba(55, 89, 78, .14); box-shadow: 0 -8px 24px rgba(44, 73, 65, .08); backdrop-filter: blur(14px); }
.tab-item { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 3px; min-height: 50px; border-radius: 13px; color: #607d73; text-decoration: none; font-size: 12px; font-weight: 700; transition: color .15s, background .15s; }
.tab-item.active { color: #287b64; background: #e8f3ef; }

@media (min-width: 768px) {
  .shell { padding: 24px 20px 48px; }
  .topbar { padding-bottom: 18px; }
  .tabbar { position: static; width: max-content; margin: 0 auto 20px; padding: 5px; border: 0; border-radius: 15px; background: #dbe8e3; box-shadow: none; backdrop-filter: none; }
  .tab-item { flex-direction: row; gap: 8px; min-height: 42px; padding: 0 26px; font-size: 13px; }
  .tab-item.active { background: #fff; box-shadow: 0 4px 12px rgba(40, 123, 100, .18); }
}

@media (max-width: 767px) {
  .el-input__inner, .el-textarea__inner { font-size: 16px; }
}
</style>
