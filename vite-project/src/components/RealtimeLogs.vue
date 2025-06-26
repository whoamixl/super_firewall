<template>
  <div class="realtime-logs-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Real-time Event Log</span>
          <el-tag :type="connectionStatus === 'Connected' ? 'success' : 'danger'">
            {{ connectionStatus }}
          </el-tag>
        </div>
      </template>
      <div class="log-display-area" ref="logArea">
        <div v-if="logMessages.length === 0 && connectionStatus !== 'Connecting...'">
          <el-empty description="No log messages received yet. Waiting for events..."></el-empty>
        </div>
        <div v-for="(log, index) in logMessages" :key="index" class="log-entry" :class="`log-${log.type}`">
          <span class="log-time">[{{ log.time }}]</span>
          <span class="log-type">[{{ log.type.toUpperCase() }}]</span>
          <span class="log-message">{{ log.message }}</span>
        </div>
      </div>
       <el-alert v-if="connectionError" title="WebSocket Connection Error" :description="connectionError" type="error" show-icon class="error-alert" @close="connectionError = ''"></el-alert>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue';
import { ElCard, ElTag, ElEmpty, ElAlert } from 'element-plus';

const logMessages = ref([]);
const connectionStatus = ref('Connecting...');
const connectionError = ref('');
const logArea = ref(null); // For auto-scrolling
let socket = null;

const MAX_LOG_MESSAGES = 200; // Keep a maximum number of messages

const connectWebSocket = () => {
  // Determine WebSocket protocol based on browser's current protocol
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${window.location.host}/ws`;

  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    connectionStatus.value = 'Connected';
    connectionError.value = '';
    logMessages.value.push({ type: 'info', message: 'WebSocket connection established.', time: new Date().toLocaleTimeString() });
  };

  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      if (logMessages.value.length >= MAX_LOG_MESSAGES) {
        logMessages.value.shift(); // Remove the oldest message
      }
      logMessages.value.push(message);
      scrollToBottom();
    } catch (e) {
      console.error("Error parsing WebSocket message:", e);
      // Add raw message if parsing fails, or a generic error message
      if (logMessages.value.length >= MAX_LOG_MESSAGES) {
        logMessages.value.shift();
      }
      logMessages.value.push({ type: 'error', message: `Received unparseable message: ${event.data}`, time: new Date().toLocaleTimeString() });
      scrollToBottom();
    }
  };

  socket.onclose = (event) => {
    connectionStatus.value = 'Disconnected';
    if (event.wasClean) {
      logMessages.value.push({ type: 'warn', message: `WebSocket connection closed cleanly, code=${event.code} reason=${event.reason}`, time: new Date().toLocaleTimeString() });
    } else {
      // e.g. server process killed or network down
      // event.code is usually 1006 in this case
      connectionError.value = `Connection died. Code: ${event.code}. Attempting to reconnect in 5 seconds...`;
      logMessages.value.push({ type: 'error', message: `WebSocket connection died. Code: ${event.code}`, time: new Date().toLocaleTimeString() });
      setTimeout(connectWebSocket, 5000); // Attempt to reconnect
    }
    scrollToBottom();
  };

  socket.onerror = (error) => {
    connectionStatus.value = 'Error';
    connectionError.value = `WebSocket Error: ${error.message || 'Unknown error'}. Check console for details.`;
    logMessages.value.push({ type: 'error', message: `WebSocket error: ${error.message || 'Check console.'}`, time: new Date().toLocaleTimeString() });
    console.error("WebSocket Error: ", error);
    scrollToBottom();
    // Reconnection is typically handled by onclose after an error.
  };
};

const scrollToBottom = () => {
  nextTick(() => {
    if (logArea.value) {
      logArea.value.scrollTop = logArea.value.scrollHeight;
    }
  });
};

onMounted(() => {
  connectWebSocket();
});

onUnmounted(() => {
  if (socket) {
    socket.close();
  }
});
</script>

<style scoped>
.realtime-logs-container {
  margin: 20px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.log-display-area {
  height: 400px;
  overflow-y: auto;
  border: 1px solid #ebeef5;
  padding: 10px;
  font-family: 'Courier New', Courier, monospace;
  font-size: 0.9em;
  background-color: #f9f9f9;
}
.log-entry {
  margin-bottom: 5px;
  padding: 2px 5px;
  border-radius: 3px;
}
.log-time {
  color: #909399;
  margin-right: 8px;
}
.log-type {
  font-weight: bold;
  margin-right: 8px;
}

/* Color coding for log types */
.log-connect {
  color: #2c8f2c; /* Darker green */
  background-color: #e8f5e9; /* Lighter green background */
}
.log-intercept {
  color: #c62828; /* Darker red */
  background-color: #ffebee; /* Lighter red background */
}
.log-info {
  color: #0277bd; /* Darker blue */
  background-color: #e1f5fe; /* Lighter blue background */
}
.log-error {
  color: #d32f2f; /* Red for errors */
  background-color: #ffcdd2; /* Light red background */
  font-weight: bold;
}
.log-warn {
  color: #f57f17; /* Darker orange/yellow */
  background-color: #fffde7; /* Lighter yellow background */
}

.log-message {
  white-space: pre-wrap; /* Allows line breaks in messages */
}
.error-alert {
  margin-top: 15px;
}
</style>
