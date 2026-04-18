# 🛡️ Verilus: Mobile Surveillance Sentry
![Version](https://img.shields.io/badge/version-1.0.0--stable-blue)

Verilus is a dedicated security utility designed to identify hidden surveillance hardware in your immediate vicinity. By combining a Go-based detection engine with native Android hardware introspection, it scans for covert cameras, tracking devices, drones, and smart glasses.

---

## 🛠️ Architecture

Verilus uses a **Hybrid Bridge** architecture to ensure logic integrity and portable analysis:

*   **Analysis Core (`veriluscore`)**: A cross-platform engine written in Go. Handles all O(1) pattern matching against manufacturer IDs, service UUIDs, and hardware fingerprints.
*   **Android Layer**: Manages BLE hardware intercepts, foreground service persistence, and the Jetpack Compose dashboard.
*   **FFI Bridge**: The analysis logic is compiled into a native AAR library via `gomobile`, protecting detection logic from static analysis.

## 🛰️ Technical Capabilities

### Bluetooth Discovery
*   **Signature Matching**: Recognizes Manufacturer IDs (DJI, Vuzix, Meta, etc.) and Service UUIDs (including FAA Remote ID `FF6B`).
*   **Name Patterning**: Analyzes advertised device names for model-specific keywords (Mavic, Anafi, XREAL, Snap).
*   **TxPower Calibration**: Uses a Log-Distance Path Loss model for proximity estimation, incorporating broadcast `txPower` for increased accuracy.
*   **Two-Phase Scanning**: Starts with `LOW_LATENCY` for immediate detection, automatically shifting to `BALANCED` mode to preserve battery life.

### Network Analysis
*   **Manufacturer Fingerprinting**: Identifies device vendors using OUI (Organizationally Unique Identifier) registries.
*   **Protocol Handshaking**: Probes active nodes for open RTSP (554) and ONVIF (3702) video streaming ports.
*   **Forensic Classification**: Categorizes nodes into `SAFE`, `SURVEILLANCE`, or `BAD_ACTOR` based on identity and active streaming signatures.

---

## 🏗️ Build Instructions

### Prerequisites
- Go 1.21+
- Android Studio & NDK
- `gomobile` tool

### 1. Build Analysis Library
```bash
gomobile bind -target=android -androidapi 28 -o android/app/libs/veriluscore.aar ./veriluscore
```

### 2. Build Android App
```bash
cd android && ./gradlew assembleDebug
```

---

## 🔒 Privacy & Safety
- **On-Device Analysis**: All analysis is performed locally. No hardware identifiers or locations are ever transmitted off-device.
- **Memory Sanitization**: Implements immediate memory scrubbing to purge analysis metadata from RAM once protection is deactivated.
- **Android 14+ Hardened**: Fully compliant with the latest foreground service and permission requirements.

---

**Developed for Privacy. Engineered because I'm still waiting for a reliable smart glass detector on iOS.**