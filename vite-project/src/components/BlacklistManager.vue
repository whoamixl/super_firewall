<template>
  <div class="blacklist-manager">
    <h2>Blacklist Management</h2>

    <!-- Form for adding new entries -->
    <form @submit.prevent="addEntry">
      <div>
        <label for="ipAddress">IP Address:</label>
        <input type="text" id="ipAddress" v.model="newEntry.ip_address" required>
      </div>
      <div>
        <label for="port">Port:</label>
        <input type="number" id="port" v.model.number="newEntry.port" required min="1" max="65535">
      </div>
      <button type="submit">Add to Blacklist</button>
    </form>
    <p v-if="errorMessage" class="error-message">{{ errorMessage }}</p>
    <p v-if="successMessage" class="success-message">{{ successMessage }}</p>

    <!-- Display existing blacklist entries -->
    <h3>Current Blacklist</h3>
    <ul v-if="blacklist.length > 0">
      <li v-for="entry in blacklist" :key="entry.id || `${entry.ip_address}:${entry.port}`">
        {{ entry.ip_address }}:{{ entry.port }}
        <button @click="deleteEntry(entry.ip_address, entry.port)">Delete</button>
      </li>
    </ul>
    <p v-else>Blacklist is currently empty.</p>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const blacklist = ref([]);
const newEntry = ref({ ip_address: '', port: null });
const errorMessage = ref('');
const successMessage = ref('');

const API_URL = '/api/blacklist';

// Function to fetch blacklist
async function fetchBlacklist() {
  try {
    const response = await fetch(API_URL);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    blacklist.value = data || []; // Handle null response from backend if empty
    successMessage.value = '';
  } catch (error) {
    console.error('Error fetching blacklist:', error);
    errorMessage.value = 'Failed to load blacklist. ' + error.message;
    blacklist.value = []; // Reset blacklist on error
  }
}

// Function to add a blacklist entry
async function addEntry() {
  errorMessage.value = '';
  successMessage.value = '';
  if (!newEntry.value.ip_address || newEntry.value.port === null) {
    errorMessage.value = 'IP Address and Port are required.';
    return;
  }
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newEntry.value),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Unknown error occurred' }));
      throw new Error(`Failed to add entry: ${response.status} ${errorData.message || ''}`);
    }
    successMessage.value = `Successfully added ${newEntry.value.ip_address}:${newEntry.value.port} to blacklist.`;
    newEntry.value = { ip_address: '', port: null }; // Reset form
    await fetchBlacklist(); // Refresh list
  } catch (error) {
    console.error('Error adding blacklist entry:', error);
    errorMessage.value = error.message;
  }
}

// Function to delete a blacklist entry
async function deleteEntry(ipAddress, port) {
  errorMessage.value = '';
  successMessage.value = '';
  try {
    const response = await fetch(API_URL, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ipAddress, port: port }),
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Unknown error occurred' }));
      throw new Error(`Failed to delete entry: ${response.status} ${errorData.message || ''}`);
    }
    successMessage.value = `Successfully deleted ${ipAddress}:${port} from blacklist.`;
    await fetchBlacklist(); // Refresh list
  } catch (error) {
    console.error('Error deleting blacklist entry:', error);
    errorMessage.value = error.message;
  }
}

// Fetch blacklist when component is mounted
onMounted(fetchBlacklist);
</script>

<style scoped>
.blacklist-manager {
  font-family: sans-serif;
  padding: 20px;
  max-width: 600px;
  margin: auto;
  background-color: #f9f9f9;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
h2, h3 {
  color: #333;
}
form div {
  margin-bottom: 10px;
}
label {
  display: inline-block;
  width: 100px;
  margin-right: 10px;
}
input[type="text"], input[type="number"] {
  padding: 8px;
  border: 1px solid #ccc;
  border-radius: 4px;
  width: calc(100% - 120px);
}
button {
  padding: 8px 15px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  margin-top: 5px;
}
button:hover {
  background-color: #0056b3;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  padding: 8px;
  border-bottom: 1px solid #eee;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
li:last-child {
  border-bottom: none;
}
li button {
  background-color: #dc3545;
  margin-left: 10px;
}
li button:hover {
  background-color: #c82333;
}
.error-message {
  color: red;
  margin-top: 10px;
}
.success-message {
  color: green;
  margin-top: 10px;
}
</style>
