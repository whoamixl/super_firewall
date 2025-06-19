<template>
  <div class="interface-selector">
    <h2>Select Network Interface</h2>
    <div v_if="message" :class="['message', messageType]">{{ message }}</div>

    <div class="controls">
      <select v-model="selectedInterface" :disabled="isLoading">
        <option disabled value="">-- Select Interface --</option>
        <option v-for="iface in interfaces" :key="iface.id" :value="iface.id">
          {{ iface.displayName }} <span v-if="iface.addresses && iface.addresses.length > 0">({{ iface.addresses.join(', ') }})</span>
        </option>
      </select>
      <button @click="startListening" :disabled="isLoading || !selectedInterface">
        {{ isLoading ? 'Loading...' : 'Start Listening' }}
      </button>
    </div>
    <div v-if="isLoading" class="loader">Loading interfaces...</div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const interfaces = ref([]);
const selectedInterface = ref('');
const isLoading = ref(false);
const message = ref('');
const messageType = ref(''); // 'success' or 'error'

async function fetchInterfaces() {
  isLoading.value = true;
  message.value = '';
  messageType.value = '';
  try {
    const response = await fetch('/api/interfaces');
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Failed to fetch interfaces' }));
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    interfaces.value = data;
    if (data.length > 0) {
      // Optionally pre-select if needed, or leave as is for user to select
      // selectedInterface.value = data[0].id; // If pre-selecting, use id
    } else {
      message.value = 'No suitable network interfaces found. Ensure the backend is running and interfaces are available.';
      messageType.value = 'error';
    }
  } catch (error) {
    console.error('Error fetching interfaces:', error);
    message.value = `Error fetching interfaces: ${error.message}`;
    messageType.value = 'error';
  } finally {
    isLoading.value = false;
  }
}

async function startListening() {
  if (!selectedInterface.value) {
    message.value = 'Please select an interface first.';
    messageType.value = 'error';
    return;
  }
  isLoading.value = true;
  message.value = '';
  messageType.value = '';

  try {
    const response = await fetch('/api/select-interface', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ interface_name: selectedInterface.value }),
    });

    const responseData = await response.json().catch(() => ({ message: 'Response was not valid JSON.' }));

    if (!response.ok) {
      const errorMsg = responseData?.message || `HTTP error! Status: ${response.status}`;
      throw new Error(errorMsg);
    }

    // Find the displayName for the success message
    const selectedIface = interfaces.value.find(iface => iface.id === selectedInterface.value);
    const displayName = selectedIface ? selectedIface.displayName : selectedInterface.value;

    message.value = responseData?.message || `Successfully started listening on ${displayName}`;
    messageType.value = 'success';
  } catch (error) {
    console.error('Error starting listening:', error);
    message.value = `Error starting listening: ${error.message || 'Unknown error'}`;
    messageType.value = 'error';
  } finally {
    isLoading.value = false;
  }
}

onMounted(() => {
  fetchInterfaces();
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
}

.controls {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 10px;
}

select {
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  flex-grow: 1;
}

button {
  padding: 8px 15px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
}

button:disabled {
  background-color: #ccc;
  cursor: not-allowed;
}

button:not(:disabled):hover {
  background-color: #0056b3;
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

.loader {
  margin-top: 10px;
  color: #555;
  font-style: italic;
}
</style>
