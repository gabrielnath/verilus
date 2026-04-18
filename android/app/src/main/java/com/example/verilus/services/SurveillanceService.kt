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
import android.os.IBinder
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.util.isNotEmpty
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import veriluscore.Veriluscore
import veriluscore.Threat

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
        
        // Flow to emit threats directly to the Main UI
        private val _threatEvents = MutableSharedFlow<Threat>(extraBufferCapacity = 50)
        val threatEvents: SharedFlow<Threat> = _threatEvents
    }

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bleScanner: BluetoothLeScanner? = null
    private var isScanning = false

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
        if (isScanning) return
        
        // 1. Promote to Foreground Service to prevent OS killing the scanner
        startForeground(NOTIFICATION_ID, buildNotification())

        // 2. Validate Permissions before accessing hardware
        if (!hasBlePermissions()) {
            Log.e(TAG, "Insufficient BLE permissions to start scan.")
            stopSelf()
            return
        }

        // 3. Configure the Native Hardware Bridge
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        val filters = mutableListOf<ScanFilter>()
        // Note: For passive wide-net scanning, filters should be left empty.
        // Rely on veriluscore (Go) to handle the O(1) matching.

        bleScanner?.startScan(filters, scanSettings, scanCallback)
        isScanning = true
        Log.i(TAG, "Verilus bridge activated. BLE scanner running.")
    }

    @SuppressLint("MissingPermission")
    private fun stopProtection() {
        if (hasBlePermissions()) {
            bleScanner?.stopScan(scanCallback)
        }
        
        // FFI Memory Sanitization: Trigger the Go GC to wipe orphaned bytes
        Veriluscore.scrub()
        
        isScanning = false
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
        // We pack the Bluetooth Hardware Address (MAC) into the UUID string to maintain AAR compatibility
        val packedPayload = "$uuidsCSV;${result.device.address}"
        val threat = Veriluscore.analyze(manDataBytes, packedPayload, result.rssi.toLong())
        
        if (threat != null && threat.category != "Unknown") {
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
