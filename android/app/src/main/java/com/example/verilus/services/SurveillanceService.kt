package com.example.verilus.services

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.util.isNotEmpty
import com.example.verilus.util.SentryLogger
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import veriluscore.Veriluscore
import veriluscore.Threat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SurveillanceService is the Native Bridge layer responsible for persistent
 * background BLE scanning. It intercepts raw hardware advertisements and 
 * prepares them to be piped into the Go `veriluscore`.
 */
class SurveillanceService : Service() {

    companion object {
        const val ACTION_START = "ACTION_START_VERILUS"
        const val ACTION_STOP = "ACTION_STOP_VERILUS"
        private const val NOTIFICATION_ID = 101
        private const val CHANNEL_ID = "VERILUS_SENTRY_CHANNEL"
        private const val TAG = "SurveillanceService"

        // Shared flow for real-time threat events — consumed by the Dashboard.
        private val _threatEvents = MutableSharedFlow<Threat>(replay = 0, extraBufferCapacity = 50)
        val threatEvents: SharedFlow<Threat> = _threatEvents

        // StateFlow that the Dashboard derives its running indicator from.
        // Survives screen rotation and process restoration unlike local `remember` state.
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        /**
         * Public API for external sources (e.g., NetworkSniffer) to push a
         * detected threat into the same UI stream as BLE events.
         */
        fun emitThreat(threat: Threat) {
            _threatEvents.tryEmit(threat)
        }
    }

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bleScanner: BluetoothLeScanner? = null
    // AtomicBoolean prevents a read-modify-write race between onStartCommand (main thread)
    // and the BLE scan callback (Binder thread).
    private val isScanning = AtomicBoolean(false)

    // D-5: Two-phase scan engine.
    // Phase 1: LOW_LATENCY for the first 30 seconds to catch nearby threats immediately.
    // Phase 2: Switch to BALANCED to preserve battery for extended protection sessions.
    private val scanModeHandler = Handler(Looper.getMainLooper())
    // The Runnable is a thin dispatcher. The actual BLE calls live in the annotated fun below,
    // which is the only correct way to apply @SuppressLint to a Runnable body.
    private val switchToBalancedRunnable = Runnable { switchToBalancedMode() }

    @SuppressLint("MissingPermission")
    private fun switchToBalancedMode() {
        if (!isScanning.get() || !hasBlePermissions()) return
        bleScanner?.stopScan(scanCallback)
        val balancedSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .build()
        bleScanner?.startScan(emptyList(), balancedSettings, scanCallback)
        SentryLogger.log("SYS: Scan mode shifted to BALANCED — battery conservation active.")
        Log.i(TAG, "Phase 2: BLE scan downgraded to BALANCED mode.")
    }

    override fun onCreate() {
        super.onCreate()
        val bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter
        bleScanner = bluetoothAdapter?.bluetoothLeScanner
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startProtection()
            ACTION_STOP -> stopProtection()
        }
        // Restart if killed by OS
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    @SuppressLint("MissingPermission")
    private fun startProtection() {
        // compareAndSet(false, true) atomically starts scanning only if not already running.
        if (!isScanning.compareAndSet(false, true)) return

        // 1. Promote to Foreground Service to prevent OS killing the scanner
        startForeground(NOTIFICATION_ID, buildNotification())
        SentryLogger.log("SYS: Verilus Forensic Engine Online.")
        _isRunning.value = true

        // 2. Validate Permissions before accessing hardware
        if (!hasBlePermissions()) {
            Log.e(TAG, "Insufficient BLE permissions to start scan.")
            isScanning.set(false)
            _isRunning.value = false
            stopSelf()
            return
        }

        // 3. Configure the Native Hardware Bridge
        // Phase 1: LOW_LATENCY for the first 30s, then switch to BALANCED in a follow-up sprint.
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        val filters = mutableListOf<ScanFilter>()
        // Note: For passive wide-net scanning, filters should be left empty.
        // Rely on veriluscore (Go) to handle the O(1) matching.

        bleScanner?.startScan(filters, scanSettings, scanCallback)
        // Schedule Phase 2: gracefully reduce to BALANCED mode after 30 seconds.
        scanModeHandler.postDelayed(switchToBalancedRunnable, 30_000L)
        Log.i(TAG, "Verilus bridge activated. BLE scanner running (Phase 1: LOW_LATENCY).")
    }

    @SuppressLint("MissingPermission")
    private fun stopProtection() {
        // Cancel any pending scan mode transitions.
        scanModeHandler.removeCallbacks(switchToBalancedRunnable)

        if (hasBlePermissions()) {
            bleScanner?.stopScan(scanCallback)
        }

        // FFI Memory Sanitization: Trigger the Go GC to wipe orphaned bytes
        Veriluscore.scrub()

        isScanning.set(false)
        _isRunning.value = false
        SentryLogger.log("SYS: Forensic Engine Offline. Releasing listeners.")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Verilus bridge deactivated.")
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            super.onScanResult(callbackType, result)
            result?.let { handleRawHardwarePacket(it) }
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>?) {
            results?.forEach { handleRawHardwarePacket(it) }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE Scan Failed with code: $errorCode")
        }
    }

    /**
     * Converts native Android APIs into byte arrays and strings to feed 
     * directly into the unified Go Architecture (veriluscore).
     */
    private fun handleRawHardwarePacket(result: ScanResult) {
        val record = result.scanRecord ?: return
        
        // 1. Extract Manufacturer Data Bytes
        val manufacturerDataMap = record.manufacturerSpecificData
        // (Just pulling the first one for demonstration, production would loop)
        val manDataBytes: ByteArray? = if (manufacturerDataMap.isNotEmpty()) {
            manufacturerDataMap.valueAt(0)
        } else null

        // 2. Extract UUID Strings
        val uuids = record.serviceUuids?.map { it.uuid.toString() } ?: emptyList()

        // -------------------------------------------------------------
        // The "Bridge" does NO threat logic.
        // We pipe the raw bytes to the Go core via the bound AAR framework.

        val uuidsCSV = uuids.joinToString(",")
        // Bridge payload format: "uuids;MAC;DeviceName"
        // The device name enables name-pattern detection in the Go engine for brands
        // (Parrot, Skydio, XREAL, Snap) that don't have registered BLE Manufacturer IDs.
        val deviceName = record.deviceName ?: ""
        val packedPayload = "$uuidsCSV;${result.device.address};$deviceName"

        // H-5: Use the actual Tx power broadcast by the device for accurate distance estimation.
        // Android returns Integer.MIN_VALUE when txPowerLevel is absent — sanitize to 0
        // so the Go engine uses its -59 dBm fallback rather than producing a NaN distance.
        val rawTxPower = record.txPowerLevel
        val txPower = if (rawTxPower < -100 || rawTxPower > 20) 0 else rawTxPower

        val threat = Veriluscore.analyze(manDataBytes, packedPayload, result.rssi.toLong(), txPower.toLong())
        
        if (threat != null) {
            SentryLogger.log("BLE: Intercepted payload from ${result.device.address}")
            if (manDataBytes != null) {
                val hexPayload = manDataBytes.joinToString("") { String.format("%02X", it) }
                SentryLogger.log("BLE: [Raw] Payload Header: 0x${hexPayload.take(12)}...")
            }
            
            SentryLogger.log("BLE: [Evidence] Proximity: ${result.rssi} dBm | Logic: ${threat.brand}")
            SentryLogger.log("BLE: [Verdict] ${threat.category.uppercase()} (Conf: ${(threat.confidence * 100).toInt()}%)")
            
            Log.w(TAG, "THREAT DETECTED: ${threat.category} (Severity: ${threat.severity} Distance: ${threat.distance}m)")
            
            // Emit to the StateFlow so the Dashboard draws the Radar immediately
            _threatEvents.tryEmit(threat)
            
            if (threat.severity >= 4) {
                // If it's highly severe, send a vibrating foreground push notification
                alertUser(threat.category, threat.distance)
            }
        }
        // -------------------------------------------------------------
    }

    @SuppressLint("MissingPermission")
    private fun alertUser(category: String, distance: Double) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🚨 Threat Detected: $category")
            .setContentText("Estimated proximity: $distance meters.")
            .setSmallIcon(android.R.drawable.ic_secure)
            .setPriority(NotificationCompat.PRIORITY_MAX) // Heads-up alert
            .setVibrate(longArrayOf(1000, 1000, 1000, 1000, 1000))
            .build()
            
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            androidx.core.content.ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return
        }
        
        androidx.core.app.NotificationManagerCompat.from(this).notify(category.hashCode(), notification)
    }

    private fun hasBlePermissions(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
        }
        return ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Verilus Sentry")
            .setContentText("Protection Active: Scanning for Threats")
            .setSmallIcon(android.R.drawable.ic_secure) // Native placeholder icon
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Verilus Background Protection",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps the passive BLE scanner running in the background."
        }
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(channel)
    }
}
