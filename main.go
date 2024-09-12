package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"golang.org/x/exp/rand"
)

const (
	dnsPort       = "53"
	rootDNSServer = "198.41.0.4" // One of the root DNS servers (a.root-servers.net)
)

var rootDNSServers = []string{
	"198.41.0.4",   // a.root-servers.net
	"199.9.14.201", // b.root-servers.net
	"192.33.4.12",  // c.root-servers.net
	// Add more root DNS servers as needed
}

func getRandomRootServer() string {
	return rootDNSServers[rand.Intn(len(rootDNSServers))]
}

// DNSHeader represents the DNS header section
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion represents the DNS question section
type DNSQuestion struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

// Helper function to create the query name
func encodeDNSName(domain string) []byte {
	parts := strings.Split(domain, ".")
	var buffer bytes.Buffer
	for _, part := range parts {
		buffer.WriteByte(byte(len(part)))
		buffer.WriteString(part)
	}
	buffer.WriteByte(0)
	return buffer.Bytes()
}

// Helper function to send the query and receive the response
func sendDNSQuery(server string, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", server+":"+dnsPort)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS query: %v", err)
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to receive DNS response: %v", err)
	}

	return response[:n], nil
}

// Construct DNS query packet
func createDNSQuery(domain string) ([]byte, error) {
	header := DNSHeader{
		ID:      0x1234, // Transaction ID
		Flags:   0x0100, // Standard query, recursion desired
		QDCount: 1,      // Number of questions
		ANCount: 0,      // No answers
		NSCount: 0,      // No authority records
		ARCount: 0,      // No additional records
	}

	question := DNSQuestion{
		QName:  encodeDNSName(domain), // Encoded domain name
		QType:  1,                     // Query type A (IPv4)
		QClass: 1,                     // Class IN (Internet)
	}

	var buffer bytes.Buffer

	// Write DNS header to buffer
	err := binary.Write(&buffer, binary.BigEndian, header)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DNS header: %v", err)
	}

	// Write DNS question to buffer
	buffer.Write(question.QName)
	err = binary.Write(&buffer, binary.BigEndian, question.QType)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DNS question type: %v", err)
	}
	err = binary.Write(&buffer, binary.BigEndian, question.QClass)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DNS question class: %v", err)
	}

	return buffer.Bytes(), nil
}

// Parse the DNS response to get the next server or the final answer
func parseDNSResponse(response []byte) (bool, string, error) {
	if len(response) < 12 {
		return false, "", fmt.Errorf("invalid DNS response")
	}

	// Parse the DNS header
	var header DNSHeader
	err := binary.Read(bytes.NewReader(response[:12]), binary.BigEndian, &header)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse DNS header: %v", err)
	}

	// Skip the question section (this is what we asked for, so we skip it)
	offset := 12
	for {
		if response[offset] == 0 {
			offset++
			break
		}
		offset++
	}
	// Skip QTYPE and QCLASS (4 bytes)
	offset += 4

	// Parse answer section if it exists
	if header.ANCount > 0 {
		fmt.Println("Answer found in response")
		_, answer, err := parseAnswerSection(response, offset, header.ANCount)
		if err != nil {
			return false, "", err
		}
		// If we found an A record (IP address), return it
		if answer != "" {
			fmt.Printf("Final Answer: %s\n", answer)
			return true, answer, nil
		}
	}

	// If no answer, parse authority section for referral (NS records)
	if header.NSCount > 0 {
		fmt.Println("No answer found, checking for referrals in authority section")
		_, nextServer, err := parseAuthoritySection(response, offset, header.NSCount)
		if err != nil {
			return false, "", err
		}
		if nextServer != "" {
			fmt.Printf("Next Server: %s\n", nextServer)
			return false, nextServer, nil
		}
	}

	// Parse additional section to get the IP address of the referred server
	if header.ARCount > 0 {
		fmt.Println("Checking additional section for referred server IP")
		_, nextServerIP, err := parseAdditionalSection(response, offset, header.ARCount)
		if err != nil {
			return false, "", err
		}
		if nextServerIP != "" {
			fmt.Printf("Referred Server IP: %s\n", nextServerIP)
			return false, nextServerIP, nil
		}
	}

	return false, "", fmt.Errorf("no answer found and no referral")
}

// Parse answer section (A record, CNAME, etc.)
func parseAnswerSection(response []byte, offset int, anCount uint16) (int, string, error) {
	for i := 0; i < int(anCount); i++ {
		offset, _ := readName(response, offset)
		rtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		rclass := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		ttl := binary.BigEndian.Uint32(response[offset : offset+4])
		offset += 4
		rdlength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		// If the record type is A (IPv4), extract the IP address
		if rtype == 1 && rclass == 1 { // A record, class IN (Internet)
			ip := net.IP(response[offset : offset+int(rdlength)])
			fmt.Printf("A record found: %s, TTL: %d\n", ip, ttl)
			return offset + int(rdlength), ip.String(), nil
		}

		// Skip over the rest of the record if it's not what we're looking for
		offset += int(rdlength)
	}
	return offset, "", nil
}

// Parse the authority section (NS records)
func parseAuthoritySection(response []byte, offset int, nsCount uint16) (int, string, error) {
	for i := 0; i < int(nsCount); i++ {
		offset, _ := readName(response, offset)
		rtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		rclass := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		ttl := binary.BigEndian.Uint32(response[offset : offset+4])
		offset += 4
		rdlength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		// If the record type is NS (nameserver), extract the domain name of the next server
		if rtype == 2 && rclass == 1 { // NS record, class IN (Internet)
			offset, nsName := readName(response, offset)
			fmt.Printf("NS record found: %s, TTL: %d\n", nsName, ttl)
			return offset, nsName, nil
		}

		// Skip over the rest of the record if it's not what we're looking for
		offset += int(rdlength)
	}
	return offset, "", nil
}

// Parse the additional section (may contain IP address of the referred nameserver)
func parseAdditionalSection(response []byte, offset int, arCount uint16) (int, string, error) {
	for i := 0; i < int(arCount); i++ {
		offset, _ := readName(response, offset)
		rtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		rclass := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		ttl := binary.BigEndian.Uint32(response[offset : offset+4])
		offset += 4
		rdlength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		// If the record type is A (IPv4), extract the IP address
		if rtype == 1 && rclass == 1 { // A record, class IN (Internet)
			ip := net.IP(response[offset : offset+int(rdlength)])
			fmt.Printf("Additional A record (referred server IP) found: %s, TTL: %d\n", ip, ttl)
			return offset + int(rdlength), ip.String(), nil
		}

		// Skip over the rest of the record if it's not what we're looking for
		offset += int(rdlength)
	}
	return offset, "", nil
}

// Helper function to read domain names (handles DNS label compression)
func readName(response []byte, offset int) (int, string) {
	var nameParts []string
	for {
		length := int(response[offset])
		if length == 0 {
			offset++
			break
		}
		// Check if it's a pointer (label compression)
		if length&0xc0 == 0xc0 {
			// Pointer: get offset from the next byte
			pointerOffset := int(binary.BigEndian.Uint16(response[offset:offset+2]) & 0x3fff)
			_, pointerName := readName(response, pointerOffset)
			nameParts = append(nameParts, pointerName)
			offset += 2
			break
		} else {
			// Normal label
			offset++
			nameParts = append(nameParts, string(response[offset:offset+length]))
			offset += length
		}
	}
	return offset, strings.Join(nameParts, ".")
}

// Recursively follow DNS hierarchy
func queryDNSHierarchy(domain string, dnsServer string, level string) {
	fmt.Printf("\n[%s] Querying DNS server: %s for domain: %s\n", level, dnsServer, domain)

	// Create DNS query
	query, err := createDNSQuery(domain)
	if err != nil {
		fmt.Printf("[%s] Error creating DNS query: %v\n", level, err)
		return
	}

	// Send query to DNS server
	response, err := sendDNSQuery(dnsServer, query)
	if err != nil {
		fmt.Printf("[%s] Error sending DNS query: %v\n", level, err)
		return
	}

	// Parse DNS response
	foundAnswer, nextServer, err := parseDNSResponse(response)
	if err != nil {
		fmt.Printf("[%s] Error parsing DNS response: %v\n", level, err)
		return
	}

	if foundAnswer {
		fmt.Printf("[%s] Received authoritative answer for domain: %s.\n", level, domain)
		return
	}

	// If no answer, continue with the next server (TLD or authoritative)
	if nextServer != "" {
		nextLevel := incrementLevel(level)
		fmt.Printf("[%s] Referring to next DNS server: %s\n", level, nextServer)
		queryDNSHierarchy(domain, nextServer, nextLevel)
	} else {
		fmt.Printf("[%s] Could not resolve domain.\n", level)
	}
}

// Increment the level based on the hierarchy
func incrementLevel(currentLevel string) string {
	switch currentLevel {
	case "Root":
		return "TLD"
	case "TLD":
		return "SLD"
	default:
		return "Subdomain"
	}
}

func main() {
	domain := "www.example.com"
	rootServer := getRandomRootServer()
	queryDNSHierarchy(domain, rootServer, "Root")
}
