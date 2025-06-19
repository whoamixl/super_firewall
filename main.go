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
	"os"
	"sync"
	"time"
)

// DB is the global database connection pool.
var DB *sql.DB

// AppConfig holds the configuration for our application.
type AppConfig struct {
	InterfaceName string
	Interface     *net.Interface
	IPv4Addr      net.IP
	MACAddr       net.HardwareAddr
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

// Global channel to send log entries to WebSocket clients.
var logChannel = make(chan LogEntry, 100)

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

// getBlacklistHandler handles GET requests to /api/blacklist.
func getBlacklistHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := GetBlacklistEntries(DB)
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

	err := AddBlacklistEntry(DB, req.IPAddress, req.Port)
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

	err := RemoveBlacklistEntry(DB, req.IPAddress, req.Port)
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

// findInterfaceConfig finds the specified network interface and extracts its configuration.
func findInterfaceConfig(name string) (*AppConfig, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get system interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Name == name {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, fmt.Errorf("failed to get addresses for interface %s: %v", name, err)
			}

			config := &AppConfig{
				InterfaceName: name,
				Interface:     &iface,
				MACAddr:       iface.HardwareAddr,
			}

			// Find the first valid IPv4 address on this interface.
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil {
						config.IPv4Addr = ipNet.IP
						log.Printf("Found configuration for interface %s:", name)
						log.Printf("  IP Address: %s", config.IPv4Addr)
						log.Printf("  MAC Address: %s", config.MACAddr)
						return config, nil
					}
				}
			}
			return nil, fmt.Errorf("no IPv4 address found for interface %s", name)
		}
	}
	return nil, fmt.Errorf("interface %s not found", name)
}

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

func main() {
	// --- Initialize Database ---
	var err error // Declare err here to avoid shadowing DB within the if block
	DB, err = InitDB("blacklist.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	// defer DB.Close() // Defer close in main or where appropriate if DB is truly global and long-lived

	err = CreateBlacklistTable(DB)
	if err != nil {
		log.Fatalf("Failed to create blacklist table: %v", err)
	}
	log.Println("Database initialized and blacklist table created successfully.")

	// Load blacklist entries
	entries, err := GetBlacklistEntries(DB)
	if err != nil {
		log.Fatalf("Failed to get blacklist entries: %v", err)
	}
	for _, entry := range entries {
		key := fmt.Sprintf("%s:%d", entry.IPAddress, entry.Port)
		currentBlacklist[key] = struct{}{}
	}
	log.Printf("Loaded %d entries into the blacklist.", len(currentBlacklist))

	listInterfaces()
	// --- 1. Configuration and Setup ---
	//interfaceName := flag.String("i", "", "Network interface name to listen on")
	//flag.Parse()
	interfaceName := "以太网"

	if interfaceName == "" {
		listInterfaces()
		os.Exit(1)
	}

	config, err := findInterfaceConfig(interfaceName)
	config.InterfaceName = "\\Device\\NPF_{31806068-E5B1-4FD3-8045-57E7F4A28738}"
	if err != nil {
		log.Fatalf("Error configuring application: %v", err)
	}

	// --- Start WebSocket server in a goroutine ---
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

		log.Println("Starting WebSocket and API server on :8080")
		// Serve static files from a 'frontend/dist' directory (create this later)
		http.Handle("/", http.FileServer(http.Dir("./frontend/dist")))
		err := http.ListenAndServe(":8080", nil) // Ensure DB is accessible if handlers need it
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()
	// Wait for the server to start, or handle this more gracefully
	time.Sleep(1 * time.Second) // Give server a moment to start

	// --- 2. Open PCAP Handle for Live Capture ---
	// Open the device for capturing, 1600 is a standard snapshot length.
	// true is for promiscuous mode.
	handle, err := pcap.OpenLive(config.InterfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", config.InterfaceName, err)
	}
	defer handle.Close()

	// --- 3. Set BPF Filter ---
	// We only want to capture TCP SYN packets destined for our IP.
	// "tcp[tcpflags] & tcp-syn != 0" ensures we only get SYN packets.
	// "and not tcp[tcpflags] & tcp-ack != 0" excludes SYN-ACK packets.
	filter := fmt.Sprintf("tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0 and dst host %s", config.IPv4Addr.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	log.Printf("Listening on %s with filter: \"%s\"", config.InterfaceName, filter)

	// --- 4. Packet Processing Loop ---
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Extract layers
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

		// Check if the source IP and port are in the blacklist
		if found {
			logToClients("intercept", "Blacklisted SYN detected from %s. Sending RST...", sourceKey)
			if err := sendRstPacket(handle, eth, ip, tcp); err != nil {
				logToClients("error", "Failed to send RST packet for blacklisted source %s: %v", sourceKey, err)
			}
		} else if !isInternalIP(ip.SrcIP) { // If not blacklisted, check if it's an external IP
			logToClients("intercept", "External SYN detected from %s:%d. Sending RST...", ip.SrcIP, tcp.SrcPort)
			if err := sendRstPacket(handle, eth, ip, tcp); err != nil {
				logToClients("error", "Failed to send RST packet for external source %s:%d: %v", ip.SrcIP, tcp.SrcPort, err)
			}
		} else { // If not blacklisted and not external (i.e., internal)
			logToClients("connect", "Internal SYN detected from %s:%d. Allowing.", ip.SrcIP, tcp.SrcPort)
		}
	}
	wg.Wait() // Keep main goroutine alive until WebSocket server stops (unlikely in this setup)
}
