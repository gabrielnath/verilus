package veriluscore

import (
	"encoding/binary"
	"math"
	"math/cmplx"
)

// AcousticThreshold defines the power level at which a high-frequency spike is flagged.
const AcousticThreshold = 0.45

// MagneticAnomalyThreshold defines the microtesla jump that triggers an alert.
const MagneticAnomalyThreshold = 25.0

// SignalResult result for the UI
type SignalResult struct {
	Level    float64
	HasThreat bool
	Info     string
}

// AcousticAnalysis checks for spikes in the ultrasonic range (18kHz - 22kHz).
// buffer is passed as []byte (raw PCM 16-bit bits) to ensure hardware compatibility.
func AcousticAnalysis(data []byte, sampleRate int64) *SignalResult {
	// Each int16 is 2 bytes.
	n := len(data) / 2
	if n < 512 {
		return &SignalResult{Level: 0, HasThreat: false, Info: "Buffer too small"}
	}

	// Decode 16-bit PCM bytes into float64 buffer for FFT processing.
	buffer := make([]float64, n)
	for i := 0; i < n; i++ {
		sample := int16(binary.LittleEndian.Uint16(data[i*2 : (i+1)*2]))
		// Normalize 16-bit signed integer to [-1.0, 1.0] range
		buffer[i] = float64(sample) / 32768.0
	}

	// Perform basic FFT
	// For production, we'd use a more optimized FFT library, 
	// but this demonstrates the logic within a single file.
	coeffs := fft(complexSamples(buffer))
	
	maxPower := 0.0
	// 44.1kHz sample rate -> indices for 18kHz-22kHz are roughly (18000/44100)*N to (22000/44100)*N
	startIdx := int(float64(18000) / float64(sampleRate) * float64(n))
	endIdx := int(float64(22000) / float64(sampleRate) * float64(n))

	if endIdx > n/2 {
		endIdx = n/2
	}

	for i := startIdx; i < endIdx; i++ {
		p := cmplx.Abs(coeffs[i])
		if p > maxPower {
			maxPower = p
		}
	}

	isThreat := maxPower > AcousticThreshold
	msg := "Acoustic Environment Clear"
	if isThreat {
		msg = "⚠️ ULTRASONIC BEACON DETECTED (Data Exfiltration Risk)"
	}

	return &SignalResult{
		Level:    maxPower,
		HasThreat: isThreat,
		Info:     msg,
	}
}

// MagneticScan checks for sudden deviations from a baseline magnetic field.
func MagneticScan(baseline float64, current float64) *SignalResult {
	diff := math.Abs(current - baseline)
	isThreat := diff > MagneticAnomalyThreshold
	
	msg := "Magnetic Field Stable"
	if isThreat {
		msg = "🧲 MAGNETIC ANOMALY (Potential Hidden Electronic Bug)"
	}

	return &SignalResult{
		Level:    diff,
		HasThreat: isThreat,
		Info:     msg,
	}
}

// Internal FFT implementation (Cooley-Tukey)
func fft(a []complex128) []complex128 {
	n := len(a)
	if n == 1 {
		return a
	}

	aEven := make([]complex128, n/2)
	aOdd := make([]complex128, n/2)
	for i := 0; i < n/2; i++ {
		aEven[i] = a[2*i]
		aOdd[i] = a[2*i+1]
	}

	yEven := fft(aEven)
	yOdd := fft(aOdd)

	y := make([]complex128, n)
	for k := 0; k < n/2; k++ {
		w := cmplx.Exp(complex(0, -2*math.Pi*float64(k)/float64(n)))
		y[k] = yEven[k] + w*yOdd[k]
		y[k+n/2] = yEven[k] - w*yOdd[k]
	}
	return y
}

func complexSamples(buffer []float64) []complex128 {
	res := make([]complex128, len(buffer))
	for i, v := range buffer {
		res[i] = complex(v, 0)
	}
	return res
}
