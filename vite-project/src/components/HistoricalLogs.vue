<template>
  <div class="historical-logs-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Historical Access Logs</span>
        </div>
      </template>
      <el-table :data="logs" style="width: 100%" v-loading="loading" stripe>
        <el-table-column prop="latest_time" label="Latest Time" sortable>
          <template #default="scope">
            {{ formatDateTime(scope.row.latest_time) }}
          </template>
        </el-table-column>
        <el-table-column prop="ip_address" label="IP Address" sortable></el-table-column>
        <el-table-column prop="access_count" label="Access Count" sortable></el-table-column>
        <el-table-column prop="interception_count" label="Interception Count" sortable></el-table-column>
      </el-table>
      <el-alert v-if="error" :title="error" type="error" show-icon class="error-alert"></el-alert>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { ElCard, ElTable, ElTableColumn, ElAlert, ElLoadingDirective } from 'element-plus';

const logs = ref([]);
const loading = ref(true);
const error = ref('');

const fetchHistoricalLogs = async () => {
  loading.value = true;
  error.value = '';
  try {
    const response = await fetch('/api/logs/history');
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    logs.value = data;
  } catch (e) {
    console.error("Failed to fetch historical logs:", e);
    error.value = `Failed to load historical logs: ${e.message}`;
  } finally {
    loading.value = false;
  }
};

const formatDateTime = (dateTimeStr) => {
  if (!dateTimeStr) return 'N/A';
  try {
    const dt = new Date(dateTimeStr);
    return dt.toLocaleString();
  } catch (e) {
    console.error("Error formatting date:", e);
    return dateTimeStr; // fallback to original string
  }
};

onMounted(() => {
  fetchHistoricalLogs();
});
</script>

<style scoped>
.historical-logs-container {
  margin: 20px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.error-alert {
  margin-top: 15px;
}
</style>
