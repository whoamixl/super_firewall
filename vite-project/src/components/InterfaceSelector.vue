<template>
  <div class="interface-selector">
    <h2>Network Interfaces</h2>
    <div v-if="message" :class="['message', messageType]">{{ message }}</div>

    <div v-if="isLoading" class="loader">Loading interface data...</div>

    <ul v-else-if="interfaces.length > 0" class="interface-list">
      <li v-for="iface in interfaces" :key="iface.id" class="interface-item">
        <div class="interface-info">
          <span class="interface-name">{{ iface.displayName }}</span>
          <span v-if="iface.addresses && iface.addresses.length > 0" class="interface-addresses">
            ({{ iface.addresses.join(', ') }})
          </span>
        </div>
        <div class="interface-status">
          <span :class="['status-indicator', { 'active': isInterfaceActive(iface.id) }]">
            {{ isInterfaceActive(iface.id) ? 'Active' : 'Inactive' }}
          </span>
          <button
            v-if="!isInterfaceActive(iface.id)"
            @click="startListeningOn(iface.id)"
            :disabled="isUpdating[iface.id]"
            class="action-button start-button">
            {{ isUpdating[iface.id] ? 'Starting...' : 'Start' }}
          </button>
          <button
            v-if="isInterfaceActive(iface.id)"
            @click="stopListeningOn(iface.id)"
            :disabled="isUpdating[iface.id]"
            class="action-button stop-button">
            {{ isUpdating[iface.id] ? 'Stopping...' : 'Stop' }}
          </button>
        </div>
      </li>
    </ul>
    <div v-else class="no-interfaces">
      No network interfaces found. Ensure the backend is running and interfaces are available.
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';

const interfaces = ref([]);
const activeInterfaceIds = ref([]);
const isLoading = ref(false); // General loading for initial data
const isUpdating = ref({}); // Per-interface loading state e.g. { "eth0": true }
const message = ref('');
const messageType = ref(''); // 'success', 'error', or 'info'

async function fetchInterfaces() {
  isLoading.value = true;
  try {
    const response = await fetch('/api/interfaces');
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Failed to fetch interfaces list' }));
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
    }
    interfaces.value = await response.json();
    if (interfaces.value.length === 0) {
      message.value = 'No suitable network interfaces found.';
      messageType.value = 'info';
    }
  } catch (error) {
    console.error('Error fetching interfaces:', error);
    message.value = `Error fetching interfaces: ${error.message}`;
    messageType.value = 'error';
    interfaces.value = [];
  } finally {
    // isLoading will be set to false after all onMounted fetches complete
  }
}

async function fetchActiveInterfaces() {
  // This can be called without setting global isLoading, as it's for refreshing status
  try {
    const response = await fetch('/api/active-interfaces');
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Failed to fetch active interfaces list' }));
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
    }
    activeInterfaceIds.value = await response.json();
  } catch (error) {
    console.error('Error fetching active interfaces:', error);
    // Potentially set a non-critical message, or rely on periodic refresh
    message.value = `Could not refresh active interfaces: ${error.message}`;
    messageType.value = 'error'; // Or a less intrusive 'info'
  }
}

const isInterfaceActive = (interfaceId) => {
  return activeInterfaceIds.value.includes(interfaceId);
};

async function startListeningOn(interfaceId) {
  isUpdating.value[interfaceId] = true;
  message.value = '';
  messageType.value = '';
  try {
    const response = await fetch('/api/select-interface', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface_name: interfaceId }),
    });
    const responseData = await response.json().catch(() => ({})); // Allow empty or non-json success
    if (!response.ok) {
      throw new Error(responseData.message || `Failed to start listening on ${interfaceId}. Status: ${response.status}`);
    }
    message.value = responseData.message || `Successfully started listening on ${interfaceId}.`;
    messageType.value = 'success';
    await fetchActiveInterfaces(); // Refresh active list
  } catch (error) {
    console.error(`Error starting listening on ${interfaceId}:`, error);
    message.value = error.message;
    messageType.value = 'error';
  } finally {
    isUpdating.value[interfaceId] = false;
  }
}

async function stopListeningOn(interfaceId) {
  isUpdating.value[interfaceId] = true;
  message.value = '';
  messageType.value = '';
  try {
    const response = await fetch('/api/stop-interface', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface_name: interfaceId }),
    });
    const responseData = await response.json().catch(() => ({})); // Allow empty or non-json success
    if (!response.ok) {
      throw new Error(responseData.message || `Failed to stop listening on ${interfaceId}. Status: ${response.status}`);
    }
    message.value = responseData.message || `Successfully stopped listening on ${interfaceId}.`;
    messageType.value = 'success';
    await fetchActiveInterfaces(); // Refresh active list
  } catch (error) {
    console.error(`Error stopping listening on ${interfaceId}:`, error);
    message.value = error.message;
    messageType.value = 'error';
  } finally {
    isUpdating.value[interfaceId] = false;
  }
}

onMounted(async () => {
  isLoading.value = true; // Start global loading
  message.value = '';
  messageType.value = '';
  await fetchInterfaces();
  await fetchActiveInterfaces();
  isLoading.value = false; // End global loading
});
</script>

<style scoped>
.interface-selector {
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 8px;
  margin-bottom: 20px;
  background-color: #f9f9f9;
}

.interface-selector h2 {
  margin-top: 0;
  color: #333;
  margin-bottom: 15px;
}

.loader {
  margin-top: 10px;
  color: #555;
  font-style: italic;
}

.interface-list {
  list-style-type: none;
  padding: 0;
}

.interface-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  border-bottom: 1px solid #eee;
}

.interface-item:last-child {
  border-bottom: none;
}

.interface-info {
  display: flex;
  flex-direction: column;
}

.interface-name {
  font-weight: bold;
  color: #2c3e50;
}

.interface-addresses {
  font-size: 0.9em;
  color: #555;
}

.interface-status {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-indicator {
  font-size: 0.9em;
  padding: 3px 8px;
  border-radius: 4px;
  font-weight: bold;
}

.status-indicator.active {
  background-color: #28a745; /* Green */
  color: white;
}

.status-indicator:not(.active) {
  background-color: #6c757d; /* Gray */
  color: white;
}

.action-button {
  padding: 6px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
  font-size: 0.9em;
}

.action-button:disabled {
  background-color: #ccc;
  cursor: not-allowed;
}

.start-button {
  background-color: #007bff; /* Blue */
  color: white;
}

.start-button:not(:disabled):hover {
  background-color: #0056b3;
}

.stop-button {
  background-color: #dc3545; /* Red */
  color: white;
}

.stop-button:not(:disabled):hover {
  background-color: #c82333;
}

.message {
  padding: 10px;
  margin-bottom: 15px;
  border-radius: 4px;
  font-weight: bold;
}

.message.success {
  background-color: #d4edda;
  color: #155724;
  border: 1px solid #c3e6cb;
}

.message.error {
  background-color: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
}

.message.info {
  background-color: #e7f3ff;
  color: #004085;
  border: 1px solid #b8daff;
}

.no-interfaces {
  padding: 10px;
  color: #555;
  font-style: italic;
}
</style>
