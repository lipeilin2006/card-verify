<script setup>
import { ref, reactive, computed } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { runRequest, errorMessage, formatTime, displayStatus, formatDuration, configReady } from "../api";

const form = reactive({ count: 1, codeLength: 20, hours: 0, days: 0, months: 1, code: "" });
const busy = ref(false);
const cards = ref([]);
const queryResult = ref(null);
const activeTab = ref("generate");

const MAX_DURATION_SECONDS = 315360000;
const totalHours = computed(() => Number(form.hours) + Number(form.days) * 24 + Number(form.months) * 720);
const totalSeconds = computed(() => totalHours.value * 3600);
const durationLabel = computed(() => {
  if (totalSeconds.value === 0) return "0 小时（永久有效）";
  const days = totalSeconds.value / 86400;
  return `合计 ${totalHours.value} 小时（约 ${days >= 1 ? Math.round(days * 10) / 10 + " 天" : "不足 1 天"}）`;
});

async function generateCards() {
  if (!configReady.value) { ElMessage.warning("请先完成连接配置"); return; }
  if (totalSeconds.value > MAX_DURATION_SECONDS) {
    ElMessage.error("生效时长不能超过 315360000 秒（87600 小时 / 3650 天）");
    return;
  }
  busy.value = true;
  cards.value = [];
  try {
    const payload = {
      count: Number(form.count),
      code_length: Number(form.codeLength),
    };
    if (totalSeconds.value > 0) payload.duration_seconds = totalSeconds.value;
    const result = await runRequest("/api/admin/cards", "POST", payload);
    cards.value = result.cards || [];
    ElMessage.success(`已生成 ${cards.value.length} 张卡密`);
  } catch (error) {
    ElMessage.error(errorMessage(error));
  } finally {
    busy.value = false;
  }
}

async function queryCard() {
  if (!configReady.value) { ElMessage.warning("请先完成连接配置"); return; }
  busy.value = true;
  queryResult.value = null;
  try {
    const result = await runRequest(`/api/admin/cards?code=${encodeURIComponent(form.code.trim())}`, "GET");
    queryResult.value = result.items?.[0] || null;
    if (queryResult.value) ElMessage.success("查询成功");
    else ElMessage.warning("未找到卡密");
  } catch (error) {
    ElMessage.error(errorMessage(error));
  } finally {
    busy.value = false;
  }
}

async function deleteQueriedCard() {
  if (!queryResult.value) return;
  try {
    await ElMessageBox.confirm(`确定删除卡密 ${queryResult.value.code}？删除后不可恢复。`, "删除确认", {
      confirmButtonText: "删除",
      cancelButtonText: "取消",
      type: "warning",
    });
  } catch {
    return;
  }
  busy.value = true;
  try {
    await runRequest("/api/admin/cards/delete", "POST", { code: queryResult.value.code });
    ElMessage.success("卡密已删除");
    queryResult.value = null;
  } catch (error) {
    ElMessage.error(errorMessage(error));
  } finally {
    busy.value = false;
  }
}

async function copyAll() {
  if (!cards.value.length) return;
  try {
    await navigator.clipboard.writeText(cards.value.join("\n"));
    ElMessage.success(`已复制全部 ${cards.value.length} 张卡密`);
  } catch {
    ElMessage.error("复制失败，请手动选择");
  }
}
</script>

<template>
  <section class="page">
    <el-tabs v-model="activeTab" class="main-tabs">
      <el-tab-pane label="生成卡密" name="generate">
        <el-form label-position="top" @submit.prevent>
          <div class="grid">
            <el-form-item label="生成数量">
              <el-input-number v-model="form.count" :min="1" :max="500" controls-position="right" />
            </el-form-item>
            <el-form-item label="卡密长度">
              <el-input-number v-model="form.codeLength" :min="6" :max="64" controls-position="right" />
            </el-form-item>
          </div>
          <el-form-item label="生效时长">
            <div class="duration-row">
              <div class="duration-cell">
                <el-input-number v-model="form.hours" :min="0" :max="87600" controls-position="right" />
                <span class="unit">小时</span>
              </div>
              <div class="duration-cell">
                <el-input-number v-model="form.days" :min="0" :max="3650" controls-position="right" />
                <span class="unit">天</span>
              </div>
              <div class="duration-cell">
                <el-input-number v-model="form.months" :min="0" :max="360" controls-position="right" />
                <span class="unit">月（30 天）</span>
              </div>
            </div>
            <p class="duration-preview" :class="{ over: totalSeconds > MAX_DURATION_SECONDS }">{{ durationLabel }}</p>
          </el-form-item>
          <el-button type="primary" class="block-button" :loading="busy" @click="generateCards">生成卡密</el-button>
        </el-form>
        <div v-if="cards.length" class="result-box" role="button" tabindex="0" title="点击复制全部" @click="copyAll" @keydown.enter="copyAll">
          <pre class="result-text">{{ cards.join("\n") }}</pre>
          <span class="copy-hint">点击复制全部（{{ cards.length }} 张，一行一个）</span>
        </div>
      </el-tab-pane>

      <el-tab-pane label="查询卡密" name="query">
        <el-form label-position="top" @submit.prevent>
          <el-form-item label="卡密">
            <el-input v-model.trim="form.code" minlength="6" maxlength="64" placeholder="输入 6-64 位卡密" clearable>
              <template #suffix><span class="counter">{{ form.code.length }}/64</span></template>
            </el-input>
          </el-form-item>
          <el-button type="primary" class="block-button" :loading="busy" @click="queryCard">查询</el-button>
        </el-form>

        <template v-if="queryResult">
          <el-descriptions :column="1" border size="small" class="details">
            <el-descriptions-item label="卡密">{{ queryResult.code }}</el-descriptions-item>
            <el-descriptions-item label="状态">
              <span :class="{ expired: displayStatus(queryResult) === 'expired' }">{{ displayStatus(queryResult) }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="绑定 HWID">
              <span class="mono">{{ queryResult.bound_hwid || "未绑定" }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="创建时间">{{ formatTime(queryResult.created_at) }}</el-descriptions-item>
            <el-descriptions-item label="激活时间">{{ formatTime(queryResult.activated_at) }}</el-descriptions-item>
            <el-descriptions-item label="失效时间">{{ formatTime(queryResult.expires_at) }}</el-descriptions-item>
            <el-descriptions-item label="生效时长">{{ formatDuration(queryResult.duration_seconds) }}</el-descriptions-item>
            <el-descriptions-item label="HWID 最近变更">{{ formatTime(queryResult.hwid_changed_at) }}</el-descriptions-item>
            <el-descriptions-item label="备注">{{ queryResult.note || "无" }}</el-descriptions-item>
          </el-descriptions>
          <el-button type="danger" class="block-button spaced" :loading="busy" @click="deleteQueriedCard">删除此卡密</el-button>
        </template>
      </el-tab-pane>
    </el-tabs>
  </section>
</template>

<style scoped>
.page { padding: 4px; }

.main-tabs :deep(.el-tabs__header) { margin-bottom: 18px; }
.main-tabs :deep(.el-tabs__nav-wrap) { margin-bottom: 0; }
.main-tabs :deep(.el-tabs__item) { flex: 1; height: 46px; font-size: 15px; font-weight: 700; }
.main-tabs :deep(.el-tabs__nav-wrap.is-top::after) { height: 2px; }

.grid { display: grid; grid-template-columns: 1fr; gap: 0; }
@media (min-width: 560px) { .grid { grid-template-columns: repeat(2, 1fr); gap: 0 14px; } }

.duration-row { display: grid; grid-template-columns: 1fr; gap: 10px; width: 100%; }
@media (min-width: 560px) { .duration-row { grid-template-columns: repeat(3, 1fr); gap: 14px; } }
.duration-cell { display: grid; gap: 5px; }
.duration-cell :deep(.el-input-number) { width: 100%; }
.duration-cell :deep(.el-input-number .el-input__wrapper) { padding-left: 11px; padding-right: 40px; }
.unit { color: #789087; font-size: 12px; font-weight: 700; text-align: center; }
.duration-preview { margin: 4px 2px 0; color: #287b64; font-size: 13px; font-weight: 700; }
.duration-preview.over { color: #b24f44; }

:deep(.el-input-number) { width: 100%; }
:deep(.el-input-number .el-input__wrapper) { padding-left: 11px; padding-right: 40px; }
.block-button { width: 100%; min-height: 46px; font-size: 15px; font-weight: 700; }
.spaced { margin-top: 16px; }

.result-box { margin-top: 16px; border: 1px solid #d7e8e1; border-radius: 11px; background: #e8f3ef; overflow: hidden; cursor: pointer; transition: border-color .15s, transform .1s; }
.result-box:active { transform: scale(.995); border-color: #39a981; }
.result-box:focus-visible { outline: 2px solid #39a981; outline-offset: 2px; }
.result-text { margin: 0; padding: 13px 14px; max-height: 280px; overflow: auto; color: #245b4d; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 14px; line-height: 1.7; letter-spacing: .05em; white-space: pre; overflow-x: auto; }
.copy-hint { display: block; padding: 8px 14px; border-top: 1px dashed #bfdbd1; color: #4f8a76; background: #f2f9f6; font-size: 12px; font-weight: 700; text-align: center; }

.counter { color: #90a49b; font-size: 12px; align-self: center; }

.details { margin-top: 4px; }
.details :deep(.el-descriptions__label.el-descriptions__cell.is-bordered-label) { width: 104px; min-width: 104px; white-space: nowrap; }
.details :deep(.el-descriptions__content.el-descriptions__cell) { word-break: break-all; }
@media (max-width: 359px) { .details :deep(.el-descriptions__label.el-descriptions__cell.is-bordered-label) { width: 88px; min-width: 88px; font-size: 12px; } }

.mono { font-family: ui-monospace, monospace; font-size: 11px; overflow-wrap: anywhere; }
.expired { color: #b24f44; font-weight: 800; }
</style>
