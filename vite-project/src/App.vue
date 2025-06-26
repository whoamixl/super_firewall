<template>
  <el-container class="app-container">
    <el-header class="app-header">
      <h1>Super Firewall</h1>
    </el-header>
    <el-main class="app-main">
      <el-tabs v-model="activeTab" type="border-card">
        <el-tab-pane label="Firewall Management" name="management">
          <div class="management-sections-container">
            <InterfaceSelector />
            <BlacklistManager />
          </div>
        </el-tab-pane>
        <el-tab-pane label="Historical Logs" name="historical">
          <HistoricalLogs v-if="activeTab === 'historical'" />
        </el-tab-pane>
        <el-tab-pane label="Real-time Logs" name="realtime">
          <RealtimeLogs v-if="activeTab === 'realtime'" />
        </el-tab-pane>
      </el-tabs>
    </el-main>
  </el-container>
</template>

<script setup>
import { ref } from 'vue';
import { ElContainer, ElHeader, ElMain, ElTabs, ElTabPane } from 'element-plus';
import BlacklistManager from './components/BlacklistManager.vue';
import InterfaceSelector from './components/InterfaceSelector.vue';
import HistoricalLogs from './components/HistoricalLogs.vue';
import RealtimeLogs from './components/RealtimeLogs.vue';

const activeTab = ref('management'); // Default to the management tab
</script>

<style lang="scss">
/* Global styles or app-specific styles */
body {
  margin: 0;
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #303133; /* Element Plus default text color */
}

.app-container {
  min-height: 100vh;
}

.app-header {
  background-color: #409EFF; // Element Plus primary color
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 20px;
  h1 {
    margin: 0;
    font-size: 1.8em;
  }
}

.app-main {
  padding: 20px;
  background-color: #f4f6f9; // A light background for the main content area
}

.el-tabs--border-card {
  box-shadow: 0 2px 12px 0 rgba(0,0,0,.1); // Add some shadow to the tabs card
}

.management-sections-container {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-around;
  align-items: flex-start;
  gap: 20px;
  padding: 20px 0; // Add some padding inside the tab
}

/* Ensure children of management-sections-container behave well */
.management-sections-container > :deep(.interface-selector),
.management-sections-container > :deep(.blacklist-manager) {
  flex-grow: 1;
  flex-basis: 400px; // Base width, adjust as needed
  max-width: 600px; // Max width to prevent them from becoming too wide
  background-color: #fff;
  border-radius: 4px;
  // box-shadow: 0 2px 4px rgba(0,0,0,.12), 0 0 6px rgba(0,0,0,.04);
  // padding: 20px; // Padding is handled by el-card typically
}

/* Remove any conflicting margins from children if necessary */
.management-sections-container > :deep(.blacklist-manager) {
  margin: 0; /* Override if there's a margin: auto */
}

/* Styling for placeholder components, can be removed if components have their own */
.historical-logs-container, .realtime-logs-container {
   padding: 10px;
}

/* IP Highlight style for reference if needed in other components,
   but primarily used in old App.vue's direct log rendering.
   RealtimeLogs.vue has its own specific styling for log entries.
*/
.highlight-ip {
  color: #007bff;
  font-weight: bold;
  background-color: #e7f3ff;
  padding: 1px 3px;
  border-radius: 2px;
}
</style>
