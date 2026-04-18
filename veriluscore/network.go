package veriluscore

import (
	"strings"
)

// OUI registries map the first 3 octets of a MAC address (Standard OUI) to a Threat Category.
// O(1) matching registry for scalable threat detection.
var ouiRegistry = map[string]string{
	// Hikvision (Over 80 known subnets, common examples below)
	"0C75D2": ThreatHiddenCamera,
	"548C81": ThreatHiddenCamera,
	"244845": ThreatHiddenCamera,

	// Dahua
	"74C929": ThreatHiddenCamera,
	"38AF29": ThreatHiddenCamera,

	// Wyze Labs
	"2CAA8E": ThreatHiddenCamera,
	"7C78B2": ThreatHiddenCamera,
	"D03F27": ThreatHiddenCamera,
	"A4DA22": ThreatHiddenCamera,
	"80482C": ThreatHiddenCamera,
	"F0C88B": ThreatHiddenCamera,

	// Tuya Smart (Often embedded in generic/cheap spy cams hardware)
	"508A06": ThreatHiddenCamera,
	"1C90FF": ThreatHiddenCamera,
	"105A17": ThreatHiddenCamera,
	"68572D": ThreatHiddenCamera,
	"84E342": ThreatHiddenCamera,

	// Miscellaneous
	"18B430": ThreatHiddenCamera,
	"0007FF": ThreatHiddenCamera,
	"60601F": ThreatHiddenCamera,
}

var brandRegistry = map[string]string{
	"0C75D2": "Hikvision",
	"548C81": "Hikvision",
	"244845": "Hikvision",
	"74C929": "Dahua",
	"38AF29": "Dahua",
	"2CAA8E": "Wyze",
	"7C78B2": "Wyze",
}

// AnalyzeNetwork evaluates localized network data natively bridged from iOS/Android.
func AnalyzeNetwork(mac string, hasRTSP bool, hasONVIF bool) *Threat {
	ip := ""
	if strings.Contains(mac, ";") {
		parts := strings.Split(mac, ";")
		mac = parts[0]
		if len(parts) > 1 {
			ip = parts[1]
		}
	}

	normalizedMAC := normalizeMAC(mac)
	
	confidence := 0.0
	severity := 0
	category := ThreatNone
	brand := "Unidentified"

	// Check if ports indicate visual surveillance
	if hasRTSP || hasONVIF {
		confidence += 0.5
		category = ThreatHiddenCamera
		severity = 2 // Baseline network threat
	}

	// Extract OUI (first 6 hex characters)
	if len(normalizedMAC) >= 6 {
		oui := normalizedMAC[:6]
		if reqCategory, exists := ouiRegistry[oui]; exists {
			category = reqCategory
			confidence += 0.4
			severity = 4 
		}
		if b, exists := brandRegistry[oui]; exists {
			brand = b
		}
	}

	// If no significant signals were found
	if confidence == 0.0 {
		return &Threat{
			Category:   ThreatNone,
			Severity:   0,
			Confidence: 0.0,
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return &Threat{
		Category:   category,
		Severity:   severity,
		Confidence: confidence,
		MAC:        mac,
		IP:         ip,
		Brand:      brand,
	}
}


// normalizeMAC safely prepares a raw string for map lookup.
// e.g., "44:65:0D:xx" -> "44650D"
func normalizeMAC(mac string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(mac))
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	return cleaned
}
