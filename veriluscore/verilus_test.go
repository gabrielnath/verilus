package veriluscore

import (
	"testing"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name         string
		manData      []byte
		uuidsCSV     string
		rssi         int
		wantCategory string
	}{
		{
			name:         "Valid Smart Glasses",
			manData:      []byte{0x42, 0x03, 0x00, 0x00}, // 0x0342 in little endian
			uuidsCSV:     "",
			rssi:         -65,
			wantCategory: ThreatSmartGlasses,
		},
		{
			name:         "Valid Drone UUID",
			manData:      nil,
			uuidsCSV:     "0xFF6B",
			rssi:         -70,
			wantCategory: ThreatUAV,
		},
		{
			name:         "Valid Drone UUID uppercase without prefix",
			manData:      nil,
			uuidsCSV:     "FF6B",
			rssi:         -40,
			wantCategory: ThreatUAV,
		},
		{
			name:         "Valid Drone UUID lowercase",
			manData:      nil,
			uuidsCSV:     "ff6b",
			rssi:         -80,
			wantCategory: ThreatUAV,
		},
		{
			name:         "No Threat",
			manData:      []byte{0x00, 0x11},
			uuidsCSV:     "1234",
			rssi:         -55,
			wantCategory: "Identified Signal", // Analyze() always returns non-nil; unknown signals return this sentinel
		},
		{
			name:         "Empty Data",
			manData:      nil,
			uuidsCSV:     "",
			rssi:         -90,
			wantCategory: "Identified Signal",
		},
		{
			name:         "Packed MAC",
			manData:      nil,
			uuidsCSV:     "FF6B;EB:04:1A:66:BD",
			rssi:         -60,
			wantCategory: ThreatUAV,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Analyze(tt.manData, tt.uuidsCSV, tt.rssi, 0)
			if got.Category != tt.wantCategory {
				t.Errorf("Analyze() Category = %v, want %v", got.Category, tt.wantCategory)
			}
		})
	}
}

func TestNormalizeUUID(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want string
	}{
		{"With 0x prefix", "0xFF6B", "FF6B"},
		{"With 0X prefix", "0XFF6B", "FF6B"},
		{"Lowercase with 0x", "0xff6b", "FF6B"},
		{"No prefix", "FF6b", "FF6B"},
		{"Whitespace padding", "  0xFF6B  ", "FF6B"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeUUID(tt.uuid); got != tt.want {
				t.Errorf("normalizeUUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScrub(t *testing.T) {
	// Call Scrub to ensure it does not panic.
	// True RAM zeroing on copies is handled native-side due to gomobile FFI boundaries.
	Scrub()
}
