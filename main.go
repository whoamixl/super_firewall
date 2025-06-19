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
	Port      int    `json:"port"`
}

// SelectInterfaceRequest defines the structure for API requests to select a network interface.
type SelectInterfaceRequest struct {
	InterfaceName string `json:"interface_name"`
}

// Global channel to send log entries to WebSocket clients.
var logChannel = make(chan LogEntry, 100)

// Global variables for packet sniffing management
var (
	activeConfig      *AppConfig
	pcapHandle        *pcap.Handle
	pcapMutex         sync.Mutex
	stopSniffing      chan struct{}
	sniffingWaitGroup sync.WaitGroup
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
// It handles stopping any existing sniffing process before starting a new one.
func startSniffing(pcapDeviceName string) error {
	pcapMutex.Lock()
	defer pcapMutex.Unlock()

	// If sniffing is already active, stop it first.
	if pcapHandle != nil {
		logToClients("info", "Stopping existing sniffing process on pcap device %s (System: %s)...", activeConfig.PcapDeviceName, activeConfig.SystemInterfaceName)
		if stopSniffing != nil {
			close(stopSniffing) // Signal the existing goroutine to stop
		}
		// pcapHandle.Close() is called by the sniffing goroutine's defer or here if error during setup
		sniffingWaitGroup.Wait() // Wait for the goroutine to finish
		logToClients("info", "Sniffing process stopped.")
		pcapHandle = nil // Explicitly nil out after goroutine is confirmed done.
		activeConfig = nil
	}

	logToClients("info", "Attempting to start sniffing on pcap device: %s", pcapDeviceName)

	cfg, err := findInterfaceConfig(pcapDeviceName)
	if err != nil {
		logToClients("error", "Failed to find suitable config for pcap device %s: %v", pcapDeviceName, err)
		return fmt.Errorf("failed to find suitable config for pcap device %s: %v", pcapDeviceName, err)
	}
	activeConfig = cfg

	// Open the device for capturing
	// Use PcapDeviceName for OpenLive
	handle, err := pcap.OpenLive(activeConfig.PcapDeviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		logToClients("error", "Error opening pcap device %s (System: %s): %v", activeConfig.PcapDeviceName, activeConfig.SystemInterfaceName, err)
		activeConfig = nil // Clear config if open fails
		return fmt.Errorf("error opening pcap device %s: %v", activeConfig.PcapDeviceName, err)
	}
	pcapHandle = handle // Store the new handle

	// Set BPF filter
	if activeConfig.IPv4Addr == nil {
		logToClients("error", "No IPv4 address configured for pcap device %s (System: %s). Cannot set BPF filter.", activeConfig.PcapDeviceName, activeConfig.SystemInterfaceName)
		pcapHandle.Close() // Close newly opened handle
		pcapHandle = nil
		activeConfig = nil
		return fmt.Errorf("no IPv4 address for pcap device %s, cannot set BPF filter", activeConfig.PcapDeviceName)
	}
	filter := fmt.Sprintf("tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0 and dst host %s", activeConfig.IPv4Addr.String())
	if err := pcapHandle.SetBPFFilter(filter); err != nil {
		logToClients("error", "Error setting BPF filter '%s' on %s: %v", filter, activeConfig.PcapDeviceName, err)
		pcapHandle.Close() // Close newly opened handle
		pcapHandle = nil
		activeConfig = nil
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	stopSniffing = make(chan struct{})
	sniffingWaitGroup.Add(1)

	go func() {
		defer sniffingWaitGroup.Done()
		// This defer ensures pcapHandle is closed when the sniffing goroutine ends,
		// either by stopSniffing signal or if packetSource closes.
		defer func() {
			pcapMutex.Lock()
			if pcapHandle != nil {
				pcapHandle.Close()
				logToClients("info", "pcap.Handle closed for %s in sniffing goroutine.", activeConfig.PcapDeviceName)
			}
			pcapMutex.Unlock()
		}()

		logToClients("info", "Listening on pcap device %s (System: %s) with filter: \"%s\"", activeConfig.PcapDeviceName, activeConfig.SystemInterfaceName, filter)
		packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
		for {
			select {
			case <-stopSniffing:
				logToClients("info", "Sniffing goroutine on %s received stop signal.", activeConfig.PcapDeviceName)
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					logToClients("info", "Packet source closed for %s.", activeConfig.PcapDeviceName)
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

				sourceKey := fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort)

				blacklistMutex.RLock()
				_, found := currentBlacklist[sourceKey]
				blacklistMutex.RUnlock()

				// Use PcapDeviceName for logging within the packet processing loop
				currentPcapDeviceName := activeConfig.PcapDeviceName // Capture for consistent logging

				if found {
					logToClients("intercept", "Blacklisted SYN from %s on %s. Sending RST...", sourceKey, currentPcapDeviceName)
					if err := sendRstPacket(pcapHandle, eth, ip, tcp); err != nil {
						logToClients("error", "Fail to send RST to blacklisted %s on %s: %v", sourceKey, currentPcapDeviceName, err)
					}
				} else if !isInternalIP(ip.SrcIP) {
					logToClients("intercept", "External SYN from %s:%d on %s. Sending RST...", ip.SrcIP, tcp.SrcPort, currentPcapDeviceName)
					if err := sendRstPacket(pcapHandle, eth, ip, tcp); err != nil {
						logToClients("error", "Fail to send RST to external %s:%d on %s: %v", ip.SrcIP, tcp.SrcPort, currentPcapDeviceName, err)
					}
				} else {
					logToClients("connect", "Internal SYN from %s:%d on %s. Allowing.", ip.SrcIP, tcp.SrcPort, currentPcapDeviceName)
				}
			}
		}
	}()

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
	// startSniffing handles stopping any previous sniffing.
	if err := startSniffing(req.InterfaceName); err != nil {
		logToClients("error", "Failed to start sniffing on %s: %v", req.InterfaceName, err)
		http.Error(w, fmt.Sprintf("Failed to start sniffing on %s: %v", req.InterfaceName, err), http.StatusInternalServerError)
		return
	}

	logToClients("info", "Successfully selected and started sniffing on interface: %s", req.InterfaceName)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully selected interface: " + req.InterfaceName})
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

	if req.IPAddress == "" || req.Port == 0 {
		http.Error(w, "IP address and port are required", http.StatusBadRequest)
		return
	}

	err := store.AddBlacklistEntry(DB, req.IPAddress, req.Port)
	if err != nil {
		// TODO: Check for unique constraint violation specifically if possible
		log.Printf("Error adding blacklist entry (%s:%d): %v", req.IPAddress, req.Port, err)
		http.Error(w, "Failed to add blacklist entry", http.StatusInternalServerError)
		return
	}

	key := fmt.Sprintf("%s:%d", req.IPAddress, req.Port)
	blacklistMutex.Lock()
	currentBlacklist[key] = struct{}{}
	blacklistMutex.Unlock()

	logToClients("info", "Added %s to blacklist via API", key)
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

	if req.IPAddress == "" || req.Port == 0 {
		http.Error(w, "IP address and port are required", http.StatusBadRequest)
		return
	}

	err := store.RemoveBlacklistEntry(DB, req.IPAddress, req.Port)
	if err != nil {
		log.Printf("Error removing blacklist entry (%s:%d): %v", req.IPAddress, req.Port, err)
		http.Error(w, "Failed to remove blacklist entry", http.StatusInternalServerError)
		return
	}

	key := fmt.Sprintf("%s:%d", req.IPAddress, req.Port)
	blacklistMutex.Lock()
	delete(currentBlacklist, key)
	blacklistMutex.Unlock()

	logToClients("info", "Removed %s from blacklist via API", key)
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
	log.Println("Database initialized and blacklist table created successfully.")

	// Load blacklist entries
	entries, err := store.GetBlacklistEntries(DB)
	if err != nil {
		log.Fatalf("Failed to get blacklist entries: %v", err)
	}
	for _, entry := range entries {
		key := fmt.Sprintf("%s:%d", entry.IPAddress, entry.Port)
		currentBlacklist[key] = struct{}{}
	}
	log.Printf("Loaded %d entries into the blacklist.", len(currentBlacklist))

	// Sniffing is no longer started automatically here.
	// It will be started via the /api/select-interface endpoint.
	// Old command-line interface selection and hardcoded values have been removed.
	log.Println("Application initialized. Select a network interface via the API to start sniffing.")

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

		// Register handler for /api/interfaces
		http.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				getInterfacesHandler(w, r)
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
