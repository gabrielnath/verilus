package veriluscore

import (
	"encoding/binary"
	"math"
	"runtime"
	"strings"
)

// Threat analysis constants representing identified device categories.
const (
	ThreatNone         = "Unknown"
	ThreatSmartGlasses = "Smart Glasses"
	ThreatUAV          = "UAV"
	ThreatHiddenCamera = "Hidden Camera"
)

// Threat defines the unified object returned to native layers.
// This allows gomobile to generate a clean class with properties.
type Threat struct {
	Category   string
	Severity   int
	Confidence float64
	Distance   float64
	IP         string
	MAC        string
	Brand      string
}

// Registry maps identifier strings to base Threat profiles.
var (
	// manIDRegistry maps 16-bit Manufacturer IDs (assigned by Bluetooth SIG) to Threats
	manIDRegistry = map[uint16]Threat{
		0x060D: {Category: ThreatSmartGlasses, Severity: 4, Confidence: 0.95, Brand: "Vuzix"},
		0x08AA: {Category: ThreatUAV, Severity: 5, Confidence: 0.95, Brand: "DJI"},
		0x027D: {Category: ThreatSmartGlasses, Severity: 5, Confidence: 0.90, Brand: "Meta"},
		0x02B0: {Category: ThreatHiddenCamera, Severity: 4, Confidence: 0.85, Brand: "GoPro"},
		0x004C: {Category: "Apple Device", Severity: 1, Confidence: 0.99, Brand: "Apple"},
		0x0075: {Category: "Samsung Device", Severity: 1, Confidence: 0.8, Brand: "Samsung"},
		0x009E: {Category: "Wearable Device", Severity: 1, Confidence: 0.9, Brand: "Bose"},
	}

	// uuidRegistry maps 16-bit or 128-bit Service UUIDs to Threats
	uuidRegistry = map[string]Threat{
		"FF6B": {Category: ThreatUAV, Severity: 5, Confidence: 0.95}, // FAA UAV Remote ID Broadcast
		"FFF0": {Category: ThreatUAV, Severity: 5, Confidence: 0.95}, // Alternate DJI Broadcast
		"FEED": {Category: "Tracking Device", Severity: 4, Confidence: 0.8},   // Tile Tracker
		"FE33": {Category: "Tracking Device", Severity: 3, Confidence: 0.8},   // Generic Tracker
		"FD69": {Category: "Tracking Device", Severity: 5, Confidence: 0.9},   // Apple FindMy (AirTag)
		"AABB": {Category: ThreatHiddenCamera, Severity: 5, Confidence: 0.85}, // Generic IP Cam Base
		"180A": {Category: "Smart Wearable", Severity: 1, Confidence: 0.70},   // Generic Device Info
	}
)

// Analyze evaluates raw hardware signals against a database of known threat fingerprints.
func Analyze(manData []byte, uuidsCSV string, rssi int) *Threat {
	var detected *Threat
	
	// 1. Manufacturer ID Check (O(1) Lookup)
	if len(manData) >= 2 {
		manID := binary.LittleEndian.Uint16(manData[:2])
		
		if threat, exists := manIDRegistry[manID]; exists {
			t := threat
			detected = &t

			// Special Handling for Apple (0x004C) - refine category based on subtype
			if manID == 0x004C && len(manData) > 2 {
				switch manData[2] {
				case 0x12: // FindMy / AirTag
					detected.Category = "AirTag / Tracker"
					detected.Severity = 5
				case 0x07, 0x02: // AirPods / Proximity
					detected.Category = "AirPods / Audio"
					detected.Severity = 1
				}
			}
		}
	}

	// 2. Service UUID Check
	if uuidsCSV != "" {
		mac := ""
		if strings.Contains(uuidsCSV, ";") {
			parts := strings.Split(uuidsCSV, ";")
			uuidsCSV = parts[0]
			if len(parts) > 1 {
				mac = parts[1]
			}
		}

		if uuidsCSV != "" {
			uuids := strings.Split(uuidsCSV, ",")
			for _, rawUUID := range uuids {
				normalizedUUID := normalizeUUID(rawUUID)
				if threat, exists := uuidRegistry[normalizedUUID]; exists {
					if detected == nil || threat.Severity > detected.Severity {
						t := threat
						detected = &t
					}
					break
				}
			}
		}

		if detected != nil && mac != "" {
			detected.MAC = mac
		}
	}


	if detected != nil {
		distance := math.Pow(10.0, float64(-59-rssi)/20.0)
		detected.Distance = math.Round(distance*100) / 100
		return detected
	}

	// Default: No known threat detected
	return &Threat{
		Category: ThreatNone,
		Severity: 0,
		Confidence: 0.0,
	}
}


// normalizeUUID safely prepares a raw string for map lookup.
// e.g., "0xff6b" -> "FF6B"
func normalizeUUID(uuid string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(uuid))
	return strings.TrimPrefix(cleaned, "0X")
}

// Scrub forces garbage collection to purge memory.
// Note: Due to FFI boundaries, gomobile copies byte arrays. 
// True zeroing of RAM must be done natively in Kotlin/Swift before calling this.
func Scrub() {
	runtime.GC()
}
