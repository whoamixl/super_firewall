<script setup>
import { ref, onMounted, onUnmounted } from 'vue';
import BlacklistManager from './components/BlacklistManager.vue';
import InterfaceSelector from './components/InterfaceSelector.vue'; // Import InterfaceSelector

// Reactive state variables
const websocket = ref(null);
const connectionLogs = ref([]);
const interceptionLogs = ref([]);
const maxLogs = 50; // Limit the number of logs to keep the display manageable

// Function to highlight IP addresses
const highlightIP = (message) => {
  // This regex matches IPv4 addresses (e.g., 192.168.1.1) and optionally a port (:8080)
  const ipRegex = /(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b)/g;
  return message.replace(ipRegex, '<span class="highlight-ip">$1</span>');
};

// Function to connect to WebSocket
const connectWebSocket = () => {
  // Use ws:// for WebSocket connection. Adjust port if your Go server is different.
  websocket.value = new WebSocket('ws://localhost:8080/ws');

  websocket.value.onopen = () => {
    console.log('WebSocket connected!');
  };

  websocket.value.onmessage = (event) => {
    try {
      const logEntry = JSON.parse(event.data);
      // Also check for 'info' and 'error' types from general server logging
      if (logEntry.type === 'connect' || logEntry.type === 'info') {
        connectionLogs.value.push(logEntry);
        if (connectionLogs.value.length > maxLogs) {
          connectionLogs.value.shift(); // Remove the oldest log
        }
      } else if (logEntry.type === 'intercept' || logEntry.type === 'error') {
        interceptionLogs.value.push(logEntry);
        if (interceptionLogs.value.length > maxLogs) {
          interceptionLogs.value.shift(); // Remove the oldest log
        }
      } else {
        // Fallback for unknown types, perhaps log them to connectionLogs or a general log
        console.warn('Unknown log type:', logEntry.type, logEntry.message);
        connectionLogs.value.push({ ...logEntry, message: `[${logEntry.type}] ${logEntry.message}`});
         if (connectionLogs.value.length > maxLogs) {
          connectionLogs.value.shift();
        }
      }
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e, event.data);
       connectionLogs.value.push({ type: 'error', message: 'Failed to parse WebSocket message: ' + event.data, time: new Date().toLocaleTimeString() });
        if (connectionLogs.value.length > maxLogs) {
          connectionLogs.value.shift();
        }
    }
  };

  websocket.value.onclose = () => {
    console.log('WebSocket disconnected. Attempting to reconnect in 3 seconds...');
    // Add a log entry for disconnection
    connectionLogs.value.push({ type: 'error', message: 'WebSocket disconnected. Attempting to reconnect...', time: new Date().toLocaleTimeString() });
    if (connectionLogs.value.length > maxLogs) {
      connectionLogs.value.shift();
    }
    setTimeout(connectWebSocket, 3000); // Attempt to reconnect
  };

  websocket.value.onerror = (error) => {
    console.error('WebSocket error:', error);
    // Add a log entry for the error
    connectionLogs.value.push({ type: 'error', message: 'WebSocket error. Check console for details.', time: new Date().toLocaleTimeString() });
    if (connectionLogs.value.length > maxLogs) {
      connectionLogs.value.shift();
    }
    websocket.value.close(); // Force close to trigger reconnect logic
  };
};

// Lifecycle Hooks using Composition API
onMounted(() => {
  connectWebSocket();
});

onUnmounted(() => {
  // Clean up WebSocket connection before component is destroyed
  if (websocket.value) {
    websocket.value.onclose = null; // Prevent reconnect logic from firing on deliberate close
    websocket.value.close();
  }
});
</script>

<template>
  <div id="app">
    <h1>Super Firewall</h1>
    <div class="management-sections-container">
      <InterfaceSelector />
      <BlacklistManager />
    </div>
    <hr />
    <h2>Firewall Logs</h2>
    <div class="log-container">
      <div class="log-section">
        <h3>System & Connection Logs</h3>
        <div class="log-entries">
          <p v-for="(log, index) in connectionLogs" :key="'conn-' + index" :class="log.type">
            <span class="timestamp">{{ log.time }}</span>
            <span v-html="highlightIP(log.message)"></span>
          </p>
        </div>
      </div>
      <div class="log-section">
        <h3>Interception & Error Logs</h3>
        <div class="log-entries">
          <p v-for="(log, index) in interceptionLogs" :key="'int-' + index" :class="log.type">
            <span class="timestamp">{{ log.time }}</span>
            <span v-html="highlightIP(log.message)"></span>
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<style lang="scss">
/* Your existing CSS remains largely the same */
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 20px; /* Adjusted margin */
}

.management-sections-container {
  display: flex;
  flex-wrap: wrap; // Allow wrapping on small screens
  justify-content: space-around; // Good for distributing space
  align-items: flex-start;
  gap: 20px;
  margin-bottom: 20px;
}

/* Target the root elements of the child components */
.management-sections-container > :deep(.interface-selector),
.management-sections-container > :deep(.blacklist-manager) {
  flex-grow: 1; // Allow them to grow
  flex-basis: 400px; // Suggest a base width. Adjust as needed.
  /* min-width: 300px; // Optional: Prevent them from becoming too small */
}

/* Override margin:auto from BlacklistManager.vue if it's problematic */
.management-sections-container > :deep(.blacklist-manager) {
  margin: 0; // Remove margin:auto to prevent centering within its flex allocation
}


h1 {
  color: #3498db;
  margin-bottom: 20px;
}
h2 {
  color: #2980b9; /* Slightly different color for section title */
  margin-top: 30px;
  margin-bottom: 15px;
}
h3 {
 color: #555; // Adjusted for less emphasis than h2
 border-bottom: 1px solid #eee;
 padding-bottom: 10px;
 margin-top: 0;
}

hr {
  border: 0;
  height: 1px;
  background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(0, 0, 0, 0.15), rgba(0, 0, 0, 0));
  margin-top: 30px;
  margin-bottom: 30px;
}

.log-container {
  display: flex;
  justify-content: space-around;
  margin-top: 20px;
  gap: 20px; /* Added gap between log sections */
}

.log-section {
  width: 48%; /* Adjusted width to account for gap */
  border: 1px solid #eee;
  border-radius: 8px;
  padding: 15px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  text-align: left;
  max-height: 300px; /* Adjusted height */
  overflow-y: auto; /* Enable scrolling */
  background-color: #fff;
}

.log-entries {
  font-family: 'Courier New', Courier, monospace;
  font-size: 0.85em; /* Slightly smaller font */
}

.log-entries p {
  margin: 6px 0; /* Adjusted margin */
  padding: 4px 6px; /* Adjusted padding */
  border-radius: 3px;
  line-height: 1.4;
}

.log-entries p.intercept {
  color: #721c24; /* Darker red text for better readability */
  background-color: #f8d7da; /* Light red background */
  border-left: 3px solid #e74c3c;
}

.log-entries p.connect {
  color: #0f5132; /* Darker green text */
  background-color: #d1e7dd; /* Light green background */
  border-left: 3px solid #27ae60;
}

.log-entries p.info { /* For general info messages */
  color: #055160;
  background-color: #cff4fc;
  border-left: 3px solid #0dcaf0;
}

.log-entries p.error { /* For explicit error messages */
  color: #721c24; /* Same as intercept */
  background-color: #f8d7da;
  border-left: 3px solid #dc3545;
  font-weight: bold;
}


.timestamp {
  /* font-weight: bold; */ /* Removed bold to make it less prominent */
  color: #666; /* Darker gray */
  margin-right: 8px; /* Increased margin */
  font-size: 0.9em;
}

.highlight-ip {
  color: #007bff; /* Changed IP highlight to blue */
  font-weight: bold;
  background-color: #e7f3ff;
  padding: 1px 3px;
  border-radius: 2px;
}
</style>
