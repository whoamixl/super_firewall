package store

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// BlacklistEntry represents an entry in the blacklist table.
type BlacklistEntry struct {
	ID        int
	IPAddress string
	Port      *int // Changed to pointer to handle nullable port
}

// InitDB opens a connection to the SQLite database and pings it.
func InitDB(dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

// CreateBlacklistTable creates the blacklist table if it doesn't exist.
func CreateBlacklistTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS blacklist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL,
		port INTEGER,
		UNIQUE(ip_address, port)
	);`
	_, err := db.Exec(query)
	return err
}

// AddBlacklistEntry adds a new IP address and port (or just IP) to the blacklist.
func AddBlacklistEntry(db *sql.DB, ipAddress string, port *int) error { // port is now *int
	query := "INSERT INTO blacklist (ip_address, port) VALUES (?, ?)"
	stmt, err := db.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	if port == nil {
		_, err = stmt.Exec(ipAddress, nil) // Insert NULL for port
	} else {
		_, err = stmt.Exec(ipAddress, *port)
	}
	return err
}

// GetBlacklistEntries retrieves all entries from the blacklist table.
func GetBlacklistEntries(db *sql.DB) ([]BlacklistEntry, error) {
	query := "SELECT id, ip_address, port FROM blacklist"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BlacklistEntry
	for rows.Next() {
		var entry BlacklistEntry
		var port sql.NullInt64 // Use sql.NullInt64 to scan nullable integer
		if err := rows.Scan(&entry.ID, &entry.IPAddress, &port); err != nil {
			return nil, err
		}
		if port.Valid {
			entry.Port = new(int)
			*entry.Port = int(port.Int64)
		} else {
			entry.Port = nil
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// RemoveBlacklistEntry removes an IP address and port (or just IP) from the blacklist.
func RemoveBlacklistEntry(db *sql.DB, ipAddress string, port *int) error { // port is now *int
	var query string
	var err error
	var stmt *sql.Stmt

	if port == nil {
		query = "DELETE FROM blacklist WHERE ip_address = ? AND port IS NULL"
		stmt, err = db.Prepare(query)
		if err != nil {
			return err
		}
		defer stmt.Close()
		_, err = stmt.Exec(ipAddress)
	} else {
		query = "DELETE FROM blacklist WHERE ip_address = ? AND port = ?"
		stmt, err = db.Prepare(query)
		if err != nil {
			return err
		}
		defer stmt.Close()
		_, err = stmt.Exec(ipAddress, *port)
	}
	return err
}
