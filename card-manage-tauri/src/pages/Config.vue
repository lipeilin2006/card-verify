<script setup>
import { onMounted, reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import { config, configReady, saveConfig, fetchVersion, setVersion, errorMessage, formatTime } from "../api";

const remote = ref(null);
const loading = ref(false);
const publishing = ref(false);
const versionForm = reactive({ url: "", notes: "", publishedAt: "" });

function handleSave() {
  saveConfig();
  ElMessage.success("配置已保存到本机");
}

async function loadRemote() {
  loading.value = true;
  try {
    remote.value = await fetchVersion();
    if (remote.value.published_at) {
      versionForm.url = remote.value.url || "";
      versionForm.notes = remote.value.notes || "";
      versionForm.publishedAt = String(remote.value.published_at);
    }
    ElMessage.success("已获取线上发布信息");
  } catch (error) {
    ElMessage.error(errorMessage(error));
  } finally {
    loading.value = false;
  }
}

async function handlePublish() {
  const raw = versionForm.publishedAt.trim();
  let publishedAt = Math.floor(Date.now() / 1000);
  if (raw) {
    if (!/^\d{9,12}$/.test(raw)) {
      ElMessage.warning("请填写秒级 Unix 时间戳（10-12 位数字），留空则用当前时间");
      return;
    }
    publishedAt = Number(raw);
  }
  publishing.value = true;
  try {
    remote.value = await setVersion({
      version: "",
      url: versionForm.url.trim(),
      notes: versionForm.notes.trim(),
      published_at: publishedAt,
    });
    ElMessage.success(`已发布（发布时间戳 ${remote.value.published_at}）`);
  } catch (error) {
    ElMessage.error(errorMessage(error));
  } finally {
    publishing.value = false;
  }
}

onMounted(() => {
  if (configReady.value) loadRemote();
});
</script>

<template>
  <section class="page">
    <div class="status-bar">
      <el-alert v-if="configReady" title="配置完整，可以正常使用管理功能" type="success" :closable="false" show-icon />
      <el-alert v-else title="配置不完整，请补全所有字段后再返回管理页" type="warning" :closable="false" show-icon />
    </div>

    <el-form label-position="top" @submit.prevent>
      <el-form-item label="Worker URL">
        <el-input v-model.trim="config.workerUrl" placeholder="https://cardverify.example.com" clearable />
      </el-form-item>
      <el-form-item label="Manager API Key">
        <el-input v-model="config.apiKey" type="password" show-password placeholder="manager_apikey" />
      </el-form-item>
      <el-form-item label="AES-256 Base64 密钥">
        <el-input v-model="config.aesKey" type="password" show-password placeholder="AES 密钥" />
      </el-form-item>
      <el-form-item label="服务端公钥 PEM">
        <el-input v-model="config.publicKey" type="textarea" :rows="5" placeholder="-----BEGIN PUBLIC KEY-----" />
      </el-form-item>
      <el-button type="primary" class="block-button" native-type="button" @click="handleSave">保存配置</el-button>
    </el-form>

    <div v-if="configReady" class="version-panel">
      <div class="panel-title">
        <span>软件发布信息</span>
        <el-tag type="info" effect="plain">按发布时间戳判断新旧</el-tag>
      </div>

      <div v-if="remote && remote.published_at" class="remote-info">
        <p>
          <span class="label">发布时间</span>
          {{ formatTime(remote.published_at) }}
          <span class="muted">（时间戳 {{ remote.published_at }}）</span>
        </p>
        <p v-if="remote.url">
          <span class="label">下载地址</span>
          <a :href="remote.url" target="_blank" rel="noreferrer">{{ remote.url }}</a>
        </p>
        <p v-if="remote.notes"><span class="label">更新说明</span>{{ remote.notes }}</p>
      </div>
      <p v-else class="muted">尚未发布过软件发布信息</p>

      <el-form label-position="top" @submit.prevent>
        <el-form-item label="发布时间戳（秒级 Unix 时间戳，留空则用当前时间）">
          <el-input v-model.trim="versionForm.publishedAt" placeholder="例如 1791188947" clearable />
        </el-form-item>
        <el-form-item label="下载 URL">
          <el-input v-model.trim="versionForm.url" placeholder="https://.../setup.exe" clearable />
        </el-form-item>
        <el-form-item label="更新说明">
          <el-input v-model="versionForm.notes" type="textarea" :rows="2" placeholder="本次更新内容（可留空）" />
        </el-form-item>
        <div class="actions">
          <el-button native-type="button" :loading="loading" @click="loadRemote">查询发布信息</el-button>
          <el-button type="primary" native-type="button" :loading="publishing" @click="handlePublish">发布</el-button>
        </div>
      </el-form>
    </div>

    <p class="hint">配置仅保存在本机 localStorage，不会上传。</p>
  </section>
</template>

<style scoped>
.page { padding: 4px; }
.status-bar { margin-bottom: 16px; }
.block-button { width: 100%; min-height: 46px; font-size: 15px; font-weight: 700; }
.version-panel { margin-top: 18px; padding: 16px; border: 1px solid #dbe8e3; border-radius: 13px; background: #f8fbfa; }
.panel-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 15px; font-weight: 700; color: #1f4d42; }
.remote-info { margin-bottom: 12px; padding: 10px 12px; border-radius: 9px; background: #eef6f3; font-size: 13px; line-height: 1.7; overflow-wrap: anywhere; }
.remote-info p { margin: 0; }
.remote-info .label { display: inline-block; min-width: 64px; color: #5d786e; }
.remote-info a { color: #287b64; }
.muted { color: #789087; font-size: 12px; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; }
.actions .el-button { margin-left: 0; }
.hint { margin: 14px 4px 0; color: #789087; font-size: 12px; text-align: center; }
:deep(.el-textarea__inner) { line-height: 1.5; font-family: ui-monospace, monospace; }
</style>
