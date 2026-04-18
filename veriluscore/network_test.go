package veriluscore

import (
	"testing"
)

func TestAnalyzeNetwork(t *testing.T) {
	tests := []struct {
		name         string
		mac          string
		ip           string
		hasRTSP      bool
		hasONVIF     bool
		wantCategory string
		wantSeverity int
	}{
		{
			name:         "Hikvision Camera with Ports",
			mac:          "44:65:0D:11:AB:22",
			ip:           "192.168.1.100",
			hasRTSP:      true,
			hasONVIF:     true,
			wantCategory: ThreatHiddenCamera,
			wantSeverity: 4,
		},
		{
			name:         "Wyze Camera Mac Only",
			mac:          "2C:AA:8E:99:FF:00",
			ip:           "192.168.1.101",
			hasRTSP:      false,
			hasONVIF:     false,
			wantCategory: ThreatHiddenCamera,
			wantSeverity: 4,
		},
		{
			name:         "Unknown Mac with RTSP",
			mac:          "00:11:22:33:44:55",
			ip:           "192.168.1.102",
			hasRTSP:      true,
			hasONVIF:     false,
			wantCategory: ThreatHiddenCamera,
			wantSeverity: 2,
		},
		{
			name:         "Safe Device",
			mac:          "AA:BB:CC:DD:EE:FF",
			ip:           "192.168.1.103",
			hasRTSP:      false,
			hasONVIF:     false,
			wantCategory: "Identified Node", // AnalyzeNetwork() always returns a Threat; unknown safe devices return this sentinel
			wantSeverity: 1,
		},
		{
			name:         "Malformed MAC (Safely Ignored)",
			mac:          "2C:AA",
			ip:           "192.168.1.104",
			hasRTSP:      false,
			hasONVIF:     false,
			wantCategory: "Identified Node",
			wantSeverity: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the packed string format (MAC;IP)
			packedMAC := tt.mac + ";" + tt.ip
			got := AnalyzeNetwork(packedMAC, tt.hasRTSP, tt.hasONVIF)
			if got.Category != tt.wantCategory {
				t.Errorf("AnalyzeNetwork() Category = %v, want %v", got.Category, tt.wantCategory)
			}
			if got.Severity != tt.wantSeverity {
				t.Errorf("AnalyzeNetwork() Severity = %v, want %v", got.Severity, tt.wantSeverity)
			}
			if got.IP != tt.ip {
				t.Errorf("AnalyzeNetwork() IP = %v, want %v", got.IP, tt.ip)
			}
		})
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name string
		mac  string
		want string
	}{
		{"Standard Colon", "44:65:0d:11:22:33", "44650D112233"},
		{"Hyphen Separated", "44-65-0D-11-22-33", "44650D112233"},
		{"Whitespace", "  44:65:0D  ", "44650D"},
		{"Lowercase", "50:d4:f7", "50D4F7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeMAC(tt.mac); got != tt.want {
				t.Errorf("normalizeMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}
