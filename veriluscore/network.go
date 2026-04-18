package veriluscore

import (
	"strings"
)

// OUI registries map the first 3 octets of a MAC address (Standard OUI) to a Threat Category.
// O(1) matching registry for scalable threat detection.
var ouiRegistry = map[string]string{
	// ── Hikvision ────────────────────────────────────────────────────────────
	// One of the world's largest CCTV manufacturers. Multiple registered OUI blocks.
	"0C75D2": ThreatHiddenCamera,
	"548C81": ThreatHiddenCamera,
	"244845": ThreatHiddenCamera,
	"C0562A": ThreatHiddenCamera,
	"28572B": ThreatHiddenCamera,
	"A0507B": ThreatHiddenCamera,
	"5C8535": ThreatHiddenCamera,
	"10001A": ThreatHiddenCamera,
	"B4A5EF": ThreatHiddenCamera, // EZVIZ (Hikvision subsidiary)

	// ── Dahua Technology ─────────────────────────────────────────────────────
	"74C929": ThreatHiddenCamera,
	"38AF29": ThreatHiddenCamera,
	"9C8ECD": ThreatHiddenCamera,
	"3CE1A1": ThreatHiddenCamera,
	"E0D0E1": ThreatHiddenCamera,

	// ── Wyze Labs ────────────────────────────────────────────────────────────
	"2CAA8E": ThreatHiddenCamera,
	"7C78B2": ThreatHiddenCamera,
	"D03F27": ThreatHiddenCamera,
	"A4DA22": ThreatHiddenCamera,
	"80482C": ThreatHiddenCamera,
	"F0C88B": ThreatHiddenCamera,

	// ── Axis Communications ──────────────────────────────────────────────────
	// Major professional IP camera manufacturer (Axis is now owned by Canon).
	"00408C": ThreatHiddenCamera,
	"ACCC8E": ThreatHiddenCamera,
	"B8A44F": ThreatHiddenCamera,

	// ── Hanwha Vision (formerly Samsung Techwin) ──────────────────────────────
	"000E6D": ThreatHiddenCamera,
	"5CF370": ThreatHiddenCamera,

	// ── Reolink Digital Technology ────────────────────────────────────────────
	"EC71DB": ThreatHiddenCamera,
	"64517E": ThreatHiddenCamera,

	// ── Uniview Technology ────────────────────────────────────────────────────
	"F4B898": ThreatHiddenCamera,

	// ── Tuya Smart (OEM platform — commonly embedded in unbranded spy cams) ───
	"508A06": ThreatHiddenCamera,
	"1C90FF": ThreatHiddenCamera,
	"105A17": ThreatHiddenCamera,
	"68572D": ThreatHiddenCamera,
	"84E342": ThreatHiddenCamera,

	// ── Miscellaneous / Unclassified Camera OUIs ─────────────────────────────
	"18B430": ThreatHiddenCamera,
	"0007FF": ThreatHiddenCamera,
	"60601F": ThreatHiddenCamera,
}

// brandRegistry maps OUIs to human-readable manufacturer names.
var brandRegistry = map[string]string{
	"0C75D2": "Hikvision",
	"548C81": "Hikvision",
	"244845": "Hikvision",
	"C0562A": "Hikvision",
	"28572B": "Hikvision",
	"A0507B": "Hikvision",
	"5C8535": "Hikvision",
	"10001A": "Hikvision",
	"B4A5EF": "Ezviz (Hikvision)",
	"74C929": "Dahua",
	"38AF29": "Dahua",
	"9C8ECD": "Dahua",
	"3CE1A1": "Dahua",
	"E0D0E1": "Dahua",
	"2CAA8E": "Wyze",
	"7C78B2": "Wyze",
	"D03F27": "Wyze",
	"00408C": "Axis",
	"ACCC8E": "Axis",
	"B8A44F": "Axis",
	"000E6D": "Hanwha Vision",
	"5CF370": "Hanwha Vision",
	"EC71DB": "Reolink",
	"64517E": "Reolink",
	"F4B898": "Uniview",
}

// ouiIsMainstreamBrand tracks OUIs that belong to known commercial vendors.
// These devices may be legitimately installed (e.g., office, lobby) and are classified
// as SURVEILLANCE rather than BAD_ACTOR, unless streaming is detected on a private network.
var ouiIsMainstream = map[string]bool{
	"0C75D2": true, "548C81": true, "244845": true, "C0562A": true, "28572B": true,
	"A0507B": true, "5C8535": true, "10001A": true, "B4A5EF": true,
	"74C929": true, "38AF29": true, "9C8ECD": true, "3CE1A1": true, "E0D0E1": true,
	"2CAA8E": true, "7C78B2": true, "D03F27": true,
	"00408C": true, "ACCC8E": true, "B8A44F": true,
	"000E6D": true, "5CF370": true, "EC71DB": true, "64517E": true, "F4B898": true,
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
	brand := "Unknown"
	ouiMatched := false

	// ── Step 1: OUI Registry Lookup (O(1)) ───────────────────────────────────
	if len(normalizedMAC) >= 6 {
		oui := normalizedMAC[:6]
		if reqCategory, exists := ouiRegistry[oui]; exists {
			category = reqCategory
			confidence += 0.4
			severity = 4
			ouiMatched = true
		}
		if b, exists := brandRegistry[oui]; exists {
			brand = b
		}
	}

	// ── Step 2: Active Video Streaming Port Detection ─────────────────────────
	if hasRTSP || hasONVIF {
		confidence += 0.5
		if category == ThreatNone {
			category = ThreatNetworkCamera
		}
		if !ouiMatched {
			// An unidentified device actively streaming video on a private network
			// is a critical signal — it cannot be explained by a known manufacturer.
			severity = 4
		} else {
			// Known brand + active streaming
			if severity < 3 {
				severity = 3
			}
		}
	}

	// ── Early Exit: No signals, return as a generic identified node ───────────
	if confidence == 0.0 {
		return &Threat{
			Category:   "Identified Node",
			Severity:   1,
			Confidence: 0.5,
			MAC:        mac,
			IP:         ip,
			Brand:      brand,
			Profile:    "SAFE",
		}
	}

	// ── Step 3: Forensic Profile Assignment ───────────────────────────────────
	profile := "SURVEILLANCE"

	// 3a. Known covert / spy-grade brand keywords (escalate immediately).
	lowBrand := strings.ToLower(brand)
	covertBrands := []string{"lawmate", "alpha tech", "aobocam", "vidcastive", "spy", "pinhole", "peephole", "covert", "hidden cam"}
	for _, actor := range covertBrands {
		if strings.Contains(lowBrand, actor) {
			profile = "BAD_ACTOR"
			severity = 5
			break
		}
	}

	// 3b. Unknown device actively streaming — cannot be attributed to a legitimate install.
	// This is the most common real-world covert-camera vector (generic Tuya/ESP32-based devices).
	if profile != "BAD_ACTOR" && !ouiMatched && (hasRTSP || hasONVIF) {
		profile = "BAD_ACTOR"
		// severity already set to 4 in Step 2
	}

	if confidence > 0.95 {
		confidence = 0.95
	}

	return &Threat{
		Category:   category,
		Severity:   severity,
		Confidence: confidence,
		MAC:        mac,
		IP:         ip,
		Brand:      brand,
		Profile:    profile,
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
