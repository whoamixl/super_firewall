package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"log"
	"net"
	"net/http"
	"super_firewall/store"
	"sync"
	"time"
)

// DB is the global database connection pool.
var DB *sql.DB

// AppConfig holds the configuration for our application.
type AppConfig struct {
	PcapDeviceName      string // Name/ID from pcap.FindAllDevs(), used by pcap.OpenLive
	SystemInterfaceName string // Name from net.Interface
	Interface           *net.Interface
	IPv4Addr            net.IP
	MACAddr             net.HardwareAddr
}

// LogEntry represents a single log message with a type.
type LogEntry struct {
	Type    string `json:"type"` // "connect" or "intercept"
	Message string `json:"message"`
	Time    string `json:"time"`
}

// BlacklistAPIRequest defines the structure for API requests to manage blacklist entries.
type BlacklistAPIRequest struct {
	IPAddress string `json:"ip_address"`
	Port      *int   `json:"port,omitempty"` // Changed to pointer, omitempty for optional
}

// SelectInterfaceRequest defines the structure for API requests to select a network interface.
type SelectInterfaceRequest struct {
	InterfaceName string `json:"interface_name"`
}

// Global channel to send log entries to WebSocket clients.
var logChannel = make(chan LogEntry, 100)

// Global variables for packet sniffing management
var (
	activeConfigs     map[string]*AppConfig
	pcapHandles       map[string]*pcap.Handle
	stopSniffingChans map[string]chan struct{}
	sniffingWaitGroup sync.WaitGroup
	// activeSniffersMutex protects activeConfigs, pcapHandles, and stopSniffingChans
	activeSniffersMutex sync.Mutex
)

// currentBlacklist stores "ip:port" strings for quick lookups.
var currentBlacklist = make(map[string]struct{})
var blacklistMutex = sync.RWMutex{} // Mutex to protect currentBlacklist

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins for development. In production, restrict this.
		return true
	},
}

// WebSocket handler to send log entries to connected clients.
func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	log.Println("WebSocket client connected.")

	// Listen for log entries and send them to the client.
	for entry := range logChannel {
		err := conn.WriteJSON(entry)
		if err != nil {
			log.Println("WebSocket write error:", err)
			break // Client disconnected or error, stop sending.
		}
	}
	log.Println("WebSocket client disconnected.")
}

// startSniffing initializes and starts the packet sniffing process on the specified interface.
// startSniffing initializes and starts packet sniffing on a specific interface.
func startSniffing(pcapDeviceName string) error {
	activeSniffersMutex.Lock()
	if _, exists := activeConfigs[pcapDeviceName]; exists {
		activeSniffersMutex.Unlock()
		logToClients("info", "Sniffing already active on %s", pcapDeviceName)
		return fmt.Errorf("sniffing already active on %s", pcapDeviceName)
	}

	cfg, err := findInterfaceConfig(pcapDeviceName)
	if err != nil {
		activeSniffersMutex.Unlock()
		logToClients("error", "Failed to find config for %s: %v", pcapDeviceName, err)
		return fmt.Errorf("failed to find config for %s: %v", pcapDeviceName, err)
	}

	handle, err := pcap.OpenLive(pcapDeviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		activeSniffersMutex.Unlock()
		logToClients("error", "Error opening pcap device %s: %v", pcapDeviceName, err)
		return fmt.Errorf("error opening pcap device %s: %v", pcapDeviceName, err)
	}

	if cfg.IPv4Addr == nil {
		activeSniffersMutex.Unlock()
		handle.Close() // Close the handle if IPv4 is not available.
		logToClients("error", "No IPv4 address for %s, cannot set BPF filter.", pcapDeviceName)
		return fmt.Errorf("no IPv4 address for %s", pcapDeviceName)
	}
	filter := fmt.Sprintf("tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0 and dst host %s", cfg.IPv4Addr.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		activeSniffersMutex.Unlock()
		handle.Close()
		logToClients("error", "Error setting BPF filter on %s: %v", pcapDeviceName, err)
		return fmt.Errorf("error setting BPF filter on %s: %v", pcapDeviceName, err)
	}

	stopChan := make(chan struct{})
	activeConfigs[pcapDeviceName] = cfg
	pcapHandles[pcapDeviceName] = handle
	stopSniffingChans[pcapDeviceName] = stopChan

	sniffingWaitGroup.Add(1)
	activeSniffersMutex.Unlock()

	logToClients("info", "Starting sniffing on %s (System: %s, IP: %s)", pcapDeviceName, cfg.SystemInterfaceName, cfg.IPv4Addr)

	go func(devName string, currentHandle *pcap.Handle, currentConfig *AppConfig, currentStopChan chan struct{}) {
		defer sniffingWaitGroup.Done()
		defer func() {
			currentHandle.Close()
			logToClients("info", "pcap.Handle closed for %s in sniffing goroutine.", devName)
			// Remove from active maps after goroutine cleanup
			activeSniffersMutex.Lock()
			delete(activeConfigs, devName)
			delete(pcapHandles, devName)
			delete(stopSniffingChans, devName)
			activeSniffersMutex.Unlock()
			logToClients("info", "Cleaned up resources for %s after sniffing stopped.", devName)

			// Attempt to remove from persisted active interfaces
			if errDb := store.RemoveActiveInterface(DB, devName); errDb != nil {
				logToClients("error", "Failed to remove persisted interface %s from DB: %v", devName, errDb)
			} else {
				logToClients("info", "Successfully removed persisted interface %s from DB.", devName)
			}
		}()

		logToClients("info", "Listening on pcap device %s (System: %s) with filter: \"%s\"", devName, currentConfig.SystemInterfaceName, filter)
		packetSource := gopacket.NewPacketSource(currentHandle, currentHandle.LinkType())

		for {
			select {
			case <-currentStopChan:
				logToClients("info", "Sniffing goroutine on %s received stop signal.", devName)
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					logToClients("info", "Packet source closed for %s.", devName)
					return
				}
				// Process packet
				ethLayer := packet.Layer(layers.LayerTypeEthernet)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				tcpLayer := packet.Layer(layers.LayerTypeTCP)

				if ethLayer == nil || ipLayer == nil || tcpLayer == nil {
					continue // Not a valid TCP/IP packet
				}

				eth := ethLayer.(*layers.Ethernet)
				ip := ipLayer.(*layers.IPv4)
				tcp := tcpLayer.(*layers.TCP)

				// Log with pcapDeviceName to distinguish logs
				specificKey := fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort)
				ipOnlyKey := ip.SrcIP.String()

				blocked := false
				blockReason := ""

				blacklistMutex.RLock()
				if _, found := currentBlacklist[specificKey]; found {
					blocked = true
					blockReason = fmt.Sprintf("IP:Port specific block (%s)", specificKey)
				} else if _, found := currentBlacklist[ipOnlyKey]; found {
					blocked = true
					blockReason = fmt.Sprintf("IP-only block (%s)", ipOnlyKey)
				}
				blacklistMutex.RUnlock()

				if blocked {
					logToClients("intercept", "Blacklisted SYN from %s (Reason: %s) on %s. Sending RST...", ip.SrcIP, blockReason, devName)
					if err := sendRstPacket(currentHandle, eth, ip, tcp); err != nil {
						logToClients("error", "Fail to send RST to blacklisted %s (Reason: %s) on %s: %v", ip.SrcIP, blockReason, devName, err)
					}
				} else if !isInternalIP(ip.SrcIP) {
					logToClients("intercept", "External SYN from %s:%d on %s. Sending RST...", ip.SrcIP, tcp.SrcPort, devName)
					if err := sendRstPacket(currentHandle, eth, ip, tcp); err != nil {
						logToClients("error", "Fail to send RST to external %s:%d on %s: %v", ip.SrcIP, tcp.SrcPort, devName, err)
					}
				} else {
					logToClients("connect", "Internal SYN from %s:%d on %s. Allowing.", ip.SrcIP, tcp.SrcPort, devName)
				}
			}
		}
	}(pcapDeviceName, handle, cfg, stopChan)

	return nil
}

// stopSniffingOnInterface signals a specific sniffing goroutine to stop.
func stopSniffingOnInterface(pcapDeviceName string) error {
	activeSniffersMutex.Lock()
	defer activeSniffersMutex.Unlock()

	stopChan, exists := stopSniffingChans[pcapDeviceName]
	if !exists {
		logToClients("info", "No active sniffing process found for %s to stop.", pcapDeviceName)
		return fmt.Errorf("no active sniffing process found for %s", pcapDeviceName)
	}

	close(stopChan) // Signal the goroutine to stop.

	// The goroutine itself is responsible for closing its pcapHandle and removing itself
	// from activeConfigs, pcapHandles, and stopSniffingChans via its defer function.
	// This function just initiates the stop.

	logToClients("info", "Stop signal sent to sniffing process on %s.", pcapDeviceName)
	return nil
}

// InterfaceDetail holds information about a network interface for API response.
type InterfaceDetail struct {
	ID          string   `json:"id"`          // pcap.Device.Name
	DisplayName string   `json:"displayName"` // pcap.Device.Description or Name
	Addresses   []string `json:"addresses"`   // IP addresses associated
}

// getInterfacesHandler handles GET requests to /api/interfaces.
func getInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logToClients("error", "Error finding pcap devices: %v", err)
		http.Error(w, "Failed to find network interfaces", http.StatusInternalServerError)
		return
	}

	var interfaceDetailsList []InterfaceDetail
	for _, device := range devices {
		var addresses []string
		for _, address := range device.Addresses {
			if address.IP != nil { // Ensure IP is not nil
				addresses = append(addresses, address.IP.String())
			}
		}

		displayName := device.Description
		if displayName == "" {
			displayName = device.Name
		}

		// Basic filtering: skip if no addresses and not clearly a loopback or "any" type interface.
		// This helps to present a cleaner list to the user.

		if len(addresses) == 0 && device.Name != "any" {
			// logToClients("debug", "Skipping interface %s (%s): no addresses and not loopback/any.", device.Name, displayName)
			continue
		}

		interfaceDetailsList = append(interfaceDetailsList, InterfaceDetail{
			ID:          device.Name,
			DisplayName: displayName,
			Addresses:   addresses,
		})
	}

	if len(interfaceDetailsList) == 0 {
		logToClients("info", "No suitable network interfaces found by pcap.FindAllDevs for the API response.")
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(interfaceDetailsList)
	if err != nil {
		logToClients("error", "Error encoding interface details to JSON: %v", err)
		http.Error(w, "Failed to encode interface details to JSON", http.StatusInternalServerError)
		return
	}
}

// selectInterfaceHandler handles POST requests to /api/select-interface.
func selectInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	var req SelectInterfaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.InterfaceName == "" {
		http.Error(w, "Interface name is required", http.StatusBadRequest)
		return
	}

	logToClients("info", "API call to select interface: %s", req.InterfaceName)

	// Attempt to start sniffing on the new interface.
	// Multiple interfaces can be active simultaneously.
	if err := startSniffing(req.InterfaceName); err != nil {
		// Check if the error is because sniffing is already active on this interface
		// This is already logged by startSniffing, but we can provide a specific client message.
		if err.Error() == fmt.Sprintf("sniffing already active on %s", req.InterfaceName) {
			logToClients("info", "Sniffing already active on %s. No action taken.", req.InterfaceName)
			// Return a success or specific status code indicating it's already running
			w.WriteHeader(http.StatusOK) // Or http.StatusConflict if preferred
			json.NewEncoder(w).Encode(map[string]string{"message": "Sniffing already active on interface: " + req.InterfaceName})
			return
		}
		logToClients("error", "Failed to start sniffing on %s: %v", req.InterfaceName, err)
		http.Error(w, fmt.Sprintf("Failed to start sniffing on %s: %v", req.InterfaceName, err), http.StatusInternalServerError)
		return
	}

	logToClients("info", "Successfully selected and started sniffing on interface: %s", req.InterfaceName)

	// Persist the newly activated interface
	if errDb := store.AddActiveInterface(DB, req.InterfaceName); errDb != nil {
		logToClients("error", "Failed to persist active interface %s to DB: %v", req.InterfaceName, errDb)
		// Not returning an HTTP error here as sniffing has started, but logging the persistence failure.
	} else {
		logToClients("info", "Successfully persisted active interface %s to DB.", req.InterfaceName)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully selected interface: " + req.InterfaceName})
}

// stopInterfaceHandler handles POST requests to /api/stop-interface.
func stopInterfaceHandler(w http.ResponseWriter, r *http.Request) {
	var req SelectInterfaceRequest // Reusing the same request structure for simplicity
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.InterfaceName == "" {
		http.Error(w, "Interface name is required", http.StatusBadRequest)
		return
	}

	logToClients("info", "API call to stop sniffing on interface: %s", req.InterfaceName)

	err := stopSniffingOnInterface(req.InterfaceName)
	if err != nil {
		logToClients("error", "Failed to stop sniffing on %s: %v", req.InterfaceName, err)
		// Check if the error means it wasn't running
		if err.Error() == fmt.Sprintf("no active sniffing process found for %s", req.InterfaceName) {
			w.WriteHeader(http.StatusOK) // Or a more specific code like 404 Not Found
			json.NewEncoder(w).Encode(map[string]string{"message": "Interface " + req.InterfaceName + " was not actively sniffing."})
			return
		}
		http.Error(w, fmt.Sprintf("Failed to stop sniffing on %s: %v", req.InterfaceName, err), http.StatusInternalServerError)
		return
	}

	// If stopSniffingOnInterface was successful, the goroutine's defer will handle DB removal.
	// No need to call store.RemoveActiveInterface here directly, as it would be redundant
	// and could race if the goroutine hasn't finished its cleanup yet.
	// The goroutine's cleanup is the single source of truth for DB removal upon stopping.

	logToClients("info", "Successfully signaled sniffing to stop on interface: %s. DB record will be removed by the sniffing goroutine.", req.InterfaceName)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully signaled sniffing to stop on interface: " + req.InterfaceName})
}

// getActiveInterfacesStatusHandler handles GET requests to /api/active-interfaces.
// It returns a list of pcap_device_name strings for all currently active sniffing interfaces.
func getActiveInterfacesStatusHandler(w http.ResponseWriter, r *http.Request) {
	activeSniffersMutex.Lock()
	defer activeSniffersMutex.Unlock()

	activeInterfaceIDs := make([]string, 0, len(activeConfigs))
	for pcapDeviceName := range activeConfigs {
		activeInterfaceIDs = append(activeInterfaceIDs, pcapDeviceName)
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(activeInterfaceIDs)
	if err != nil {
		logToClients("error", "Error encoding active interface IDs to JSON: %v", err)
		http.Error(w, "Failed to encode active interfaces to JSON", http.StatusInternalServerError)
		return
	}
}

// getBlacklistHandler handles GET requests to /api/blacklist.
func getBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := store.GetBlacklistEntries(DB)
	if err != nil {
		log.Printf("Error getting blacklist entries: %v", err)
		http.Error(w, "Failed to retrieve blacklist", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		log.Printf("Error encoding blacklist entries to JSON: %v", err)
		http.Error(w, "Failed to encode blacklist to JSON", http.StatusInternalServerError)
	}
}

// addBlacklistHandler handles POST requests to /api/blacklist.
func addBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	var req BlacklistAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.IPAddress == "" {
		http.Error(w, "IP address is required", http.StatusBadRequest)
		return
	}
	// Port can be nil (for IP-only) or a valid port number.
	// We might want to disallow port 0 if it's not nil, as it's often not a valid port for blocking.
	// For now, if Port is provided (not nil) and is 0, it's treated as an IP-only block too.
	// Or, we can return an error for port 0 if it's not nil.
	// Let's assume nil means IP-only, and a 0 port is invalid if not nil.
	// The task description says: "If req.Port is nil or *req.Port == 0 ... pass nil to store.AddBlacklistEntry"
	// This implies 0 is also IP-only. Let's stick to that for now.

	var effectivePort *int
	var key string
	var logMessagePort string

	if req.Port == nil { // IP-only block
		effectivePort = nil
		key = req.IPAddress
		logMessagePort = "IP-only"
	} else { // Port is specified
		// Optional: Validate port range if needed, e.g., *req.Port > 0 && *req.Port <= 65535
		// if *req.Port == 0 { // As per current interpretation, treat 0 as IP-only as well
		// 	 effectivePort = nil
		// 	 key = req.IPAddress
		// 	 logMessagePort = "IP-only (port 0 specified)"
		// } else
		if *req.Port <= 0 || *req.Port > 65535 { // Explicitly make port 0 invalid if *req.Port is not nil
			http.Error(w, "Invalid port number. Port must be between 1 and 65535, or omitted for IP-only blocking.", http.StatusBadRequest)
			return
		}
		effectivePort = req.Port
		key = fmt.Sprintf("%s:%d", req.IPAddress, *req.Port)
		logMessagePort = fmt.Sprintf("port %d", *req.Port)
	}

	err := store.AddBlacklistEntry(DB, req.IPAddress, effectivePort)
	if err != nil {
		log.Printf("Error adding blacklist entry (%s, %s): %v", req.IPAddress, logMessagePort, err)
		http.Error(w, "Failed to add blacklist entry. It might already exist or there was a database error.", http.StatusInternalServerError) // Consider more specific errors
		return
	}

	blacklistMutex.Lock()
	currentBlacklist[key] = struct{}{}
	blacklistMutex.Unlock()

	logToClients("info", "Added %s (%s) to blacklist via API", req.IPAddress, logMessagePort)
	w.WriteHeader(http.StatusCreated)
}

// removeBlacklistHandler handles DELETE requests to /api/blacklist.
func removeBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	var req BlacklistAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.IPAddress == "" {
		http.Error(w, "IP address is required", http.StatusBadRequest)
		return
	}

	var effectivePort *int
	var key string
	var logMessagePort string

	if req.Port == nil { // IP-only block removal
		effectivePort = nil
		key = req.IPAddress
		logMessagePort = "IP-only"
	} else { // Port is specified for removal
		// if *req.Port == 0 { // Treat 0 as IP-only for removal key consistency
		// 	effectivePort = nil
		// 	key = req.IPAddress
		// 	logMessagePort = "IP-only (port 0 specified)"
		// } else
		if *req.Port <= 0 || *req.Port > 65535 {
			http.Error(w, "Invalid port number. Port must be between 1 and 65535, or omitted for IP-only blocking.", http.StatusBadRequest)
			return
		}
		effectivePort = req.Port
		key = fmt.Sprintf("%s:%d", req.IPAddress, *req.Port)
		logMessagePort = fmt.Sprintf("port %d", *req.Port)
	}

	err := store.RemoveBlacklistEntry(DB, req.IPAddress, effectivePort)
	if err != nil {
		log.Printf("Error removing blacklist entry (%s, %s): %v", req.IPAddress, logMessagePort, err)
		// It's common for remove operations to not find the entry, which isn't always an error.
		// However, store.RemoveBlacklistEntry doesn't distinguish "not found" from other errors.
		// For simplicity, we'll return a generic error. A more robust solution might check sql.ErrNoRows if possible.
		http.Error(w, "Failed to remove blacklist entry", http.StatusInternalServerError)
		return
	}

	blacklistMutex.Lock()
	delete(currentBlacklist, key)
	blacklistMutex.Unlock()

	logToClients("info", "Removed %s (%s) from blacklist via API", req.IPAddress, logMessagePort)
	w.WriteHeader(http.StatusOK) // Or http.StatusNoContent
}

// logToClients sends a log entry to the global log channel.
func logToClients(logType, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Type:    logType,
		Message: msg,
		Time:    time.Now().Format("15:04:05"), // Format time for display
	}
	select {
	case logChannel <- entry:
		// Sent successfully
	default:
		// Channel is full, drop the log to avoid blocking.
		log.Println("Warning: Log channel full, dropping log:", msg)
	}
	log.Printf(format, args...) // Still log to console for debugging
}

// isInternalIP checks if the given IP address is an internal (private or loopback) IP.
func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// sendRstPacket constructs and sends a TCP RST packet to terminate a connection.
// It crafts a new packet based on the properties of the incoming packet.
func sendRstPacket(handle *pcap.Handle, incomingEth *layers.Ethernet, incomingIP *layers.IPv4, incomingTCP *layers.TCP) error {
	// 1. Create the Ethernet layer.
	// The source MAC is our MAC, and the destination MAC is the original sender's MAC.
	eth := &layers.Ethernet{
		SrcMAC:       incomingEth.DstMAC,
		DstMAC:       incomingEth.SrcMAC,
		EthernetType: incomingEth.EthernetType,
	}

	// 2. Create the IPv4 layer.
	// The source IP is the original destination IP, and the destination is the original source IP.
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    incomingIP.DstIP,
		DstIP:    incomingIP.SrcIP,
	}

	// 3. Create the TCP layer (the RST packet).
	// A valid RST packet must have the ACK flag set.
	// The sequence number is set to the incoming packet's acknowledgment number.
	// The acknowledgment number is the incoming sequence number + 1.
	tcp := &layers.TCP{
		SrcPort:    incomingTCP.DstPort, // Swap ports
		DstPort:    incomingTCP.SrcPort,
		Seq:        incomingTCP.Ack,
		Ack:        incomingTCP.Seq + 1,
		RST:        true,
		ACK:        true,
		Window:     0,
		DataOffset: 5, // Basic TCP header size
	}
	// Set the TCP checksum. This is important for the packet to be accepted.
	err := tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		return fmt.Errorf("failed to set network layer for checksum: %v", err)
	}

	// 4. Serialize the layers into a byte buffer.
	// gopacket will handle calculating checksums and lengths for us.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	if err != nil {
		return fmt.Errorf("failed to serialize layers: %v", err)
	}

	// 5. Send the crafted packet.
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send RST packet: %v", err)
	}

	logToClients("intercept", "Sent RST from %s:%d to %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	return nil
}

// findInterfaceConfig attempts to find a usable system network interface that corresponds
// to the given pcap device name and has a valid IPv4 address.
func findInterfaceConfig(pcapDeviceNameToMatch string) (*AppConfig, error) {
	// Step 1: Find the target pcap.Device and its IPs.
	pcapDevices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to list pcap devices: %v", err)
	}

	var targetPcapDevice pcap.Interface
	foundPcapDevice := false
	for _, device := range pcapDevices {
		if device.Name == pcapDeviceNameToMatch {
			targetPcapDevice = device
			foundPcapDevice = true
			break
		}
	}

	if !foundPcapDevice {
		return nil, fmt.Errorf("pcap device %s not found", pcapDeviceNameToMatch)
	}

	var pcapDeviceIPv4s []net.IP
	for _, addr := range targetPcapDevice.Addresses {
		if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
			pcapDeviceIPv4s = append(pcapDeviceIPv4s, addr.IP)
		}
	}
	if len(pcapDeviceIPv4s) == 0 {
		return nil, fmt.Errorf("pcap device %s has no non-loopback IPv4 addresses", pcapDeviceNameToMatch)
	}

	// Step 2: Find the corresponding net.Interface.
	sysInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get system interfaces: %v", err)
	}

	for _, sysIface := range sysInterfaces {
		addrs, err := sysIface.Addrs()
		if err != nil {
			log.Printf("Warning: failed to get addresses for system interface %s: %v", sysIface.Name, err)
			continue // Try next system interface
		}

		for _, sysAddr := range addrs {
			var sysIP net.IP
			if ipNet, ok := sysAddr.(*net.IPNet); ok {
				sysIP = ipNet.IP
			} else if ipAddr, ok := sysAddr.(*net.IPAddr); ok {
				sysIP = ipAddr.IP
			} else {
				continue
			}

			if sysIP.To4() == nil || sysIP.IsLoopback() {
				continue
			}

			// Compare with IPs from the target pcap device
			for _, pcapIP := range pcapDeviceIPv4s {
				if sysIP.Equal(pcapIP) {
					// Match found!
					config := &AppConfig{
						PcapDeviceName:      targetPcapDevice.Name,
						SystemInterfaceName: sysIface.Name,
						Interface:           &sysIface,
						MACAddr:             sysIface.HardwareAddr,
						IPv4Addr:            sysIP, // Use the matched IP
					}
					log.Printf("Found matching configuration for pcap device %s:", pcapDeviceNameToMatch)
					log.Printf("  Pcap Device Name: %s", config.PcapDeviceName)
					log.Printf("  System Interface Name: %s", config.SystemInterfaceName)
					log.Printf("  IP Address: %s", config.IPv4Addr)
					log.Printf("  MAC Address: %s", config.MACAddr)
					return config, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("could not find a system interface with a common IPv4 address for pcap device %s. Pcap IPs: %v", pcapDeviceNameToMatch, pcapDeviceIPv4s)
}

/*
// listInterfaces prints all available network interfaces.
func listInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}
	fmt.Println("Available network interfaces:")
	for _, device := range devices {
		fmt.Printf("  - Name: %s\n", device.Name)
		for _, address := range device.Addresses {
			fmt.Printf("    - IP address: %s\n", address.IP)
		}
	}
	fmt.Println("\nPlease choose an interface and run again with the -i flag.")
	fmt.Printf("Example: %s -i <interface_name>\n", os.Args[0])
}
*/

func main() {
	// Initialize maps for multi-interface support
	activeConfigs = make(map[string]*AppConfig)
	pcapHandles = make(map[string]*pcap.Handle)
	stopSniffingChans = make(map[string]chan struct{})

	// --- Initialize Database ---
	var err error // Declare err here to avoid shadowing DB within the if block
	DB, err = store.InitDB("blacklist.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	// defer DB.Close() // Defer close in main or where appropriate if DB is truly global and long-lived

	err = store.CreateBlacklistTable(DB)
	if err != nil {
		log.Fatalf("Failed to create blacklist table: %v", err)
	}
	log.Println("Blacklist table created successfully.")

	// Create active interfaces table
	err = store.CreateActiveInterfacesTable(DB)
	if err != nil {
		log.Fatalf("Failed to create active_interfaces table: %v", err)
	}
	log.Println("Active interfaces table created successfully.")

	log.Println("Database initialized.")

	// Load blacklist entries
	entries, err := store.GetBlacklistEntries(DB)
	if err != nil {
		log.Fatalf("Failed to get blacklist entries: %v", err)
	}
	for _, entry := range entries {
		var key string
		if entry.Port == nil { // IP-only entry
			key = entry.IPAddress
		} else { // IP:Port entry
			key = fmt.Sprintf("%s:%d", entry.IPAddress, *entry.Port)
		}
		currentBlacklist[key] = struct{}{}
	}
	log.Printf("Loaded %d entries into the blacklist.", len(currentBlacklist))

	// Load and start persisted active interfaces
	persistedInterfaces, err := store.GetActiveInterfaces(DB)
	if err != nil {
		log.Fatalf("Failed to get persisted active interfaces: %v", err)
	}

	if len(persistedInterfaces) > 0 {
		log.Printf("Found %d persisted active interfaces. Attempting to restart sniffing on them...", len(persistedInterfaces))
		for _, deviceName := range persistedInterfaces {
			logToClients("info", "Attempting to restart sniffing on persisted interface: %s", deviceName)
			if errSniff := startSniffing(deviceName); errSniff != nil {
				logToClients("error", "Failed to restart sniffing on %s: %v. It might need to be manually re-selected or may no longer be available.", deviceName, errSniff)
				// If startup fails for a persisted interface, remove it from DB to avoid repeated failures.
				if errDb := store.RemoveActiveInterface(DB, deviceName); errDb != nil {
					logToClients("error", "Additionally, failed to remove problematic persisted interface %s from DB: %v", deviceName, errDb)
				} else {
					logToClients("info", "Problematic persisted interface %s removed from DB.", deviceName)
				}
			} else {
				logToClients("info", "Successfully restarted sniffing on persisted interface: %s", deviceName)
				// No need to re-add to DB as it was already there.
			}
		}
	} else {
		log.Println("No persisted active interfaces found.")
	}

	log.Println("Application initialized. API is ready.")
	// --- Start WebSocket server and API endpoints in a goroutine ---
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		http.HandleFunc("/ws", wsHandler)

		// Register API handlers for blacklist management
		http.HandleFunc("/api/blacklist", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				getBlacklistHandler(w, r)
			case http.MethodPost:
				addBlacklistHandler(w, r)
			case http.MethodDelete:
				removeBlacklistHandler(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Register handler for /api/select-interface
		http.HandleFunc("/api/select-interface", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				selectInterfaceHandler(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Register handler for /api/stop-interface
		http.HandleFunc("/api/stop-interface", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				stopInterfaceHandler(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Register handler for /api/interfaces
		http.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				getInterfacesHandler(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		// Register handler for /api/active-interfaces
		http.HandleFunc("/api/active-interfaces", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				getActiveInterfacesStatusHandler(w, r)
			} else {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		})

		log.Println("Starting WebSocket and API server on :8080")
		// Serve static files from a 'frontend/dist' directory (create this later)
		http.Handle("/", http.FileServer(http.Dir("./frontend/dist")))
		err := http.ListenAndServe(":8080", nil) // Ensure DB is accessible if handlers need it
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Keep main goroutine alive until the HTTP server goroutine stops.
	// If http.ListenAndServe returns (which it ideally shouldn't unless there's a fatal error),
	// wg.Wait() will allow the program to exit cleanly.
	wg.Wait()
	log.Println("HTTP server goroutine finished. Exiting.")
}
