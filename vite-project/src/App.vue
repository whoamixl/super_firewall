<script setup>
import { ref, onMounted, onUnmounted } from 'vue';
import BlacklistManager from './components/BlacklistManager.vue'; // Import BlacklistManager

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
      if (logEntry.type === 'connect') {
        connectionLogs.value.push(logEntry);
        if (connectionLogs.value.length > maxLogs) {
          connectionLogs.value.shift(); // Remove the oldest log
        }
      } else if (logEntry.type === 'intercept') {
        interceptionLogs.value.push(logEntry);
        if (interceptionLogs.value.length > maxLogs) {
          interceptionLogs.value.shift(); // Remove the oldest log
        }
      } else {
        console.warn('Unknown log type:', logEntry.type);
      }
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e, event.data);
    }
  };

  websocket.value.onclose = () => {
    console.log('WebSocket disconnected. Attempting to reconnect in 3 seconds...');
    setTimeout(connectWebSocket, 3000); // Attempt to reconnect
  };

  websocket.value.onerror = (error) => {
    console.error('WebSocket error:', error);
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
    websocket.value.close();
  }
});
</script>

<template>
  <div id="app">
    <h1>Super Firewall</h1>
    <BlacklistManager />
    <hr />
    <h2>Firewall Logs</h2>
    <div class="log-container">
      <div class="log-section">
        <h3>Connection Logs</h3>
        <div class="log-entries">
          <p v-for="(log, index) in connectionLogs" :key="'conn-' + index" :class="log.type">
            <span class="timestamp">{{ log.time }}</span>
            <span v-html="highlightIP(log.message)"></span>
          </p>
        </div>
      </div>
      <div class="log-section">
        <h2>Interception Logs</h2>
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

<script setup>
      <div class="log-section">
        <h3>Interception Logs</h3>
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
 color: #2ecc71; /* Original h2 color */
 border-bottom: 1px solid #eee;
 padding-bottom: 10px;
 margin-top: 0;
}

hr {
  border: 0;
  height: 1px;
  background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(0, 0, 0, 0.75), rgba(0, 0, 0, 0));
  margin-top: 30px;
  margin-bottom: 30px;
}

.log-container {
  display: flex;
  justify-content: space-around;
  margin-top: 20px;
}

.log-section {
  width: 45%;
  border: 1px solid #eee;
  border-radius: 8px;
  padding: 15px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  text-align: left;
  max-height: 400px; /* Adjusted height */
  overflow-y: auto; /* Enable scrolling */
}

.log-entries {
  font-family: 'Courier New', Courier, monospace;
  font-size: 0.9em;
}

.log-entries p {
  margin: 5px 0;
  padding: 3px 5px;
  border-radius: 3px;
  background-color: #f9f9f9;
}

.log-entries p.intercept {
  color: #e74c3c; /* Red for intercepted logs */
  background-color: #ffecec;
}

.log-entries p.connect {
  color: #27ae60; /* Green for connection logs */
  background-color: #e8f9e8;
}

.timestamp {
  font-weight: bold;
  color: #888;
  margin-right: 5px;
}

.highlight-ip {
  color: #e74c3c; /* Bright red */
  font-weight: bold;
}
</style>
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
      if (logEntry.type === 'connect') {
        connectionLogs.value.push(logEntry);
        if (connectionLogs.value.length > maxLogs) {
          connectionLogs.value.shift(); // Remove the oldest log
        }
      } else if (logEntry.type === 'intercept') {
        interceptionLogs.value.push(logEntry);
        if (interceptionLogs.value.length > maxLogs) {
          interceptionLogs.value.shift(); // Remove the oldest log
        }
      } else {
        console.warn('Unknown log type:', logEntry.type);
      }
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e, event.data);
    }
  };

  websocket.value.onclose = () => {
    console.log('WebSocket disconnected. Attempting to reconnect in 3 seconds...');
    setTimeout(connectWebSocket, 3000); // Attempt to reconnect
  };

  websocket.value.onerror = (error) => {
    console.error('WebSocket error:', error);
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
    websocket.value.close();
  }
});
</script>

<style lang="scss">
/* Your existing CSS remains largely the same */
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}

h1 {
  color: #3498db;
}

.log-container {
  display: flex;
  justify-content: space-around;
  margin-top: 20px;
}

.log-section {
  width: 45%;
  border: 1px solid #eee;
  border-radius: 8px;
  padding: 15px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  text-align: left;
  max-height: 500px; /* Limit height */
  overflow-y: auto; /* Enable scrolling */
}

h2 {
  color: #2ecc71;
  border-bottom: 1px solid #eee;
  padding-bottom: 10px;
  margin-top: 0;
}

.log-entries {
  font-family: 'Courier New', Courier, monospace;
  font-size: 0.9em;
}

.log-entries p {
  margin: 5px 0;
  padding: 3px 5px;
  border-radius: 3px;
  background-color: #f9f9f9;
}

.log-entries p.intercept {
  color: #e74c3c; /* Red for intercepted logs */
  background-color: #ffecec;
}

.log-entries p.connect {
  color: #27ae60; /* Green for connection logs */
  background-color: #e8f9e8;
}

.timestamp {
  font-weight: bold;
  color: #888;
  margin-right: 5px;
}

.highlight-ip {
  color: #e74c3c; /* Bright red */
  font-weight: bold;
}
</style>
