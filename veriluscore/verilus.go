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
	ThreatSmartGlasses  = "Smart Glasses"
	ThreatUAV           = "UAV"
	ThreatHiddenCamera  = "Hidden Camera"
	ThreatNetworkCamera = "Network Camera"
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
	Profile    string // SAFE, SURVEILLANCE, or BAD_ACTOR
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
	"FF6B": {Category: ThreatUAV, Severity: 5, Confidence: 0.98}, // FAA ASTM F3411 Remote ID — legally mandated drone broadcast
		"FFF0": {Category: ThreatUAV, Severity: 5, Confidence: 0.95}, // Alternate DJI Broadcast
		"FEED": {Category: "Tracking Device", Severity: 4, Confidence: 0.8},   // Tile Tracker
		"FE33": {Category: "Tracking Device", Severity: 3, Confidence: 0.8},   // Generic Tracker
		"FD69": {Category: "Tracking Device", Severity: 5, Confidence: 0.9},   // Apple FindMy (AirTag)
		"AABB": {Category: ThreatHiddenCamera, Severity: 5, Confidence: 0.85}, // Generic IP Cam Base
		"180A": {Category: "Smart Wearable", Severity: 1, Confidence: 0.70},   // Generic Device Info
	}
)

// Analyze evaluates raw hardware signals against a database of known threat fingerprints.
// txPower: The Tx power level broadcast by the device (from ScanRecord.getTxPowerLevel()).
// Pass 0 when unavailable — the engine will fall back to the standard -59 dBm reference.
func Analyze(manData []byte, uuidsCSV string, rssi int, txPower int) *Threat {
	var detected *Threat
	mac := ""
	deviceName := ""

	// Extract MAC and optional device name from the packed bridge payload.
	// Format: "uuid1,uuid2;MAC;DeviceName" (DeviceName is omitted in older bridge versions)
	if strings.Contains(uuidsCSV, ";") {
		parts := strings.Split(uuidsCSV, ";")
		uuidsCSV = parts[0]
		if len(parts) > 1 {
			mac = parts[1]
		}
		if len(parts) > 2 {
			deviceName = strings.ToLower(strings.TrimSpace(parts[2]))
		}
	}

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

	// 3. Device Name Pattern Matching
	// Primary detection pathway for brands without registered BLE Manufacturer IDs:
	// Parrot, Skydio, Autel, Yuneec (drones) and XREAL, Snap, Solos (smart glasses).
	// Also reinforces ManID matches when the name independently confirms the category.
	if detected == nil && deviceName != "" {
		if nameMatch := matchDeviceName(deviceName); nameMatch != nil {
			t := *nameMatch
			detected = &t
		}
	}

	if detected != nil {
		if mac != "" {
			detected.MAC = mac
		}

		// Judge forensic profile by category.
		switch {
		case strings.Contains(detected.Category, "Tracker") || strings.Contains(detected.Category, "AirTag"):
			// Trackers following a person are the clearest form of hostile surveillance.
			detected.Profile = "BAD_ACTOR"
		case strings.Contains(detected.Category, "Hidden Camera"):
			// A camera actively broadcasting BLE in an unknown space is covert by definition.
			detected.Profile = "BAD_ACTOR"
			if detected.Severity < 5 {
				detected.Severity = 5
			}
		case strings.Contains(detected.Category, "Device") ||
			strings.Contains(detected.Category, "Audio") ||
			strings.Contains(detected.Category, "Wearable"):
			detected.Profile = "SAFE"
		default:
			detected.Profile = "SURVEILLANCE"
		}

		if detected.Confidence > 0.95 {
			detected.Confidence = 0.95
		}
		detected.Distance = calcDistance(rssi, txPower)
		return detected
	}

	// Default: Return the signal metadata even if it's not a known threat
	return &Threat{
		Category:   "Identified Signal",
		Severity:   1,
		Confidence: 0.5,
		Distance:   calcDistance(rssi, txPower),
		MAC:        mac,
		Profile:    "SAFE",
	}
}

// calcDistance computes the estimated distance in metres using the Log-Distance Path Loss model.
// refRSSI is the Tx power level (RSSI at 1 metre). Uses -59 dBm as the industry default when
// the device does not broadcast its Tx power or the value is out of a sane physical range.
func calcDistance(rssi int, txPower int) float64 {
	refRSSI := -59
	if txPower != 0 && txPower >= -100 && txPower <= 20 {
		refRSSI = txPower
	}
	distance := math.Pow(10.0, float64(refRSSI-rssi)/20.0)
	return math.Round(distance*100) / 100
}


// matchDeviceName performs pattern-based threat detection against the BLE advertised device name.
// This is the primary detection pathway for devices without registered BLE Manufacturer IDs
// (Parrot, Skydio, XREAL, Snap Spectacles, etc.).
// Patterns are ordered most-specific first to prevent generic terms shadowing brand names.
func matchDeviceName(name string) *Threat {
	type namePattern struct {
		sub  string
		brand string
		conf float64
	}

	// ── Drone patterns ──────────────────────────────────────────────────────
	dronePatterns := []namePattern{
		{"mavic",      "DJI",        0.92},
		{"phantom",    "DJI",        0.92},
		{"air 2",      "DJI",        0.90},
		{"air2",       "DJI",        0.90},
		{"dji-",       "DJI",        0.90},
		{"dji ",       "DJI",        0.90},
		{"mini-",      "DJI",        0.88},
		{"anafi",      "Parrot",     0.92},
		{"bebop",      "Parrot",     0.88},
		{"parrot",     "Parrot",     0.88},
		{"skydio",     "Skydio",     0.90},
		{"autel",      "Autel",      0.88},
		{"yuneec",     "Yuneec",     0.85},
		{"typhoon",    "Yuneec",     0.85},
		{"potensic",   "Potensic",   0.80},
		{"holy stone", "Holy Stone", 0.80},
		{"quadcopter", "Unknown",    0.65},
		{"drone",      "Unknown",    0.65},
	}

	// ── Smart glasses patterns ───────────────────────────────────────────────
	glassesPatterns := []namePattern{
		{"vuzix",      "Vuzix",      0.92},
		{"xreal",      "XREAL",      0.92},
		{"nreal",      "XREAL",      0.90},
		{"spectacles", "Snap",       0.90},
		{"solos",      "Solos",      0.85},
		{"rayneo",     "TCL RayNeo", 0.85},
		{"envision",   "Envision",   0.82},
		{"inmo",       "INMO",       0.82},
		{"smart glass","Unknown",    0.70},
	}

	for _, p := range dronePatterns {
		if strings.Contains(name, p.sub) {
			return &Threat{
				Category:   ThreatUAV,
				Severity:   5,
				Confidence: p.conf,
				Brand:      p.brand,
			}
		}
	}
	for _, p := range glassesPatterns {
		if strings.Contains(name, p.sub) {
			return &Threat{
				Category:   ThreatSmartGlasses,
				Severity:   4,
				Confidence: p.conf,
				Brand:      p.brand,
			}
		}
	}
	return nil
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
