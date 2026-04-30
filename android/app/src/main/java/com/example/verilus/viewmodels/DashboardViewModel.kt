package com.example.verilus.viewmodels

import android.app.Application
import android.bluetooth.BluetoothManager
import androidx.compose.runtime.*
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.verilus.services.SurveillanceService
import com.example.verilus.util.SentryLogger
import com.example.verilus.util.SignalIntelligence
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import veriluscore.Threat

data class TacticalAlert(val title: String, val message: String, val id: Long = System.currentTimeMillis())

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val signalIntel = SignalIntelligence(application)
    
    // Hardware Support Check
    var isBleSupported by mutableStateOf(true)
    var isBleEnabled by mutableStateOf(true)

    // --- State Streams ---
    val isRunning = SurveillanceService.isRunning
    private val _threats = mutableStateListOf<Threat>()
    val threats: List<Threat> get() = _threats

    val magLevel = signalIntel.magneticLevel
    val magBaseline = signalIntel.baselineLevel
    val magResult = signalIntel.magneticResult
    val acousticAlert = signalIntel.acousticThreat
    
    // --- Local UI State ---
    var selectedTab by mutableIntStateOf(0)
    var isNetworkScanning by mutableStateOf(false)
    var isBleScanning by mutableStateOf(false)
    var isJamming by mutableStateOf(false)
    var jamMode by mutableStateOf(SignalIntelligence.JamMode.ULTRASONIC_SWEEP)
    
    private val _consoleLogs = mutableStateListOf<String>()
    val consoleLogs: List<String> get() = _consoleLogs

    val alertQueue = mutableStateListOf<TacticalAlert>()

    private var networkScanJob: Job? = null
    private var bleScanJob: Job? = null
    
    // Rate limiter for SIGINT notifications (30-second window)
    private val notificationCooldowns = mutableMapOf<String, Long>()

    init {
        runCatching {
            val bluetoothManager = application.getSystemService(BluetoothManager::class.java)
            isBleSupported = bluetoothManager?.adapter != null
            isBleEnabled = bluetoothManager?.adapter?.isEnabled == true

            // Initial log event
            _consoleLogs.add(0, "Initializing Verilus Engine...")

            viewModelScope.launch {
                SurveillanceService.threatEvents.collect { threat ->
                    val isDuplicate = _threats.any { 
                        (threat.mac.isNotEmpty() && it.mac == threat.mac) || 
                        (threat.ip.isNotEmpty() && it.ip == threat.ip) 
                    }
                    if (!isDuplicate) _threats.add(0, threat)
                }
            }

            viewModelScope.launch {
                SentryLogger.events.collect { log ->
                    if (log.isNotEmpty()) {
                        _consoleLogs.add(0, log)
                        if (_consoleLogs.size > 50) _consoleLogs.removeAt(50)
                    }
                }
            }

            // Monitoring Magnetic Threats for System Notifications
            viewModelScope.launch {
                signalIntel.magneticResult.collect { result ->
                    if (result?.hasThreat == true) {
                        sendNotification("Flux Deviation", "Localized magnetic flux exceeds baseline. Forensic evidence: ${result.info}")
                    }
                }
            }

            // Monitoring Acoustic Threats
            viewModelScope.launch {
                signalIntel.acousticThreat.collect { isThreat ->
                    if (isThreat) {
                        sendNotification("Acoustic Signature", "Covert ultrasonic beacon pattern detected.")
                    }
                }
            }
        }.onFailure {
            logSys("CRITICAL: Engine startup inhibited - ${it.message}")
        }
    }

    /**
     * Starts the passive forensic monitors (Magnetic/Acoustic).
     * This should be called once permissions are granted.
     */
    fun startMonitors() {
        runCatching {
            signalIntel.startMagneticScan()
            signalIntel.startAcousticAnalysis {}
            logSys("Forensic monitors initialized via UI hook.")
        }.onFailure {
            logSys("WARN: Forensic monitors could not initialize - ${it.message}")
        }
    }

    fun setTab(index: Int) { 
        // Safety Cutoff: Stop jammer when leaving the Signal Intel tab
        if (isJamming) {
            signalIntel.stopJammer()
            isJamming = false
            logSys("Jammer auto-cutoff triggered by navigation.")
        }
        selectedTab = index 
    }

    fun toggleBleScan(onStart: () -> Unit, onStop: () -> Unit) {
        if (!isBleEnabled || !isBleSupported) return
        
        if (isRunning.value) {
            networkScanJob?.cancel()
            onStop()
        } else {
            isBleScanning = true
            bleScanJob = viewModelScope.launch {
                delay(1500)
                onStart()
                isBleScanning = false
            }
        }
    }

    fun startNetworkScan() {
        if (isNetworkScanning) return
        isNetworkScanning = true
        networkScanJob = viewModelScope.launch {
            delay(1500)
            try { com.example.verilus.network.NetworkSniffer().scanLocalNetwork() }
            finally { isNetworkScanning = false }
        }
    }

    fun toggleJammer() {
        if (isJamming) {
            signalIntel.stopJammer()
            isJamming = false
        } else {
            signalIntel.startJammer(jamMode)
            isJamming = true
        }
    }

    fun updateJamMode(mode: SignalIntelligence.JamMode) {
        // Safety: Always stop and reset the engine when changing modes
        if (isJamming) {
            signalIntel.stopJammer()
            isJamming = false
            logSys("Countermeasure reset for mode configuration.")
        }
        jamMode = mode
    }

    fun clearThreats() { 
        _threats.clear() 
        signalIntel.resetBaseline()
        logSys("Forensic data cleared. Re-calibrating ambient levels.")
    }

    private fun logSys(message: String) {
        val time = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.getDefault()).format(java.util.Date())
        _consoleLogs.add(0, "[$time] SYS: $message")
        if (_consoleLogs.size > 50) _consoleLogs.removeAt(50)
    }

    private fun sendNotification(title: String, message: String) {
        val now = System.currentTimeMillis()
        val lastSent = notificationCooldowns[title] ?: 0L
        if (now - lastSent < 30_000L) {
            // Log to console only during cooldown to keep the user informed
            logSys("INFO: $title detected (Notification suppressed by 30s cooldown)")
            return
        }
        notificationCooldowns[title] = now

        val context = signalIntel.getContext()
        val notificationManager = context.getSystemService(android.content.Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
        
        // Show high-priority system notification
        val notification = androidx.core.app.NotificationCompat.Builder(context, "VERILUS_SENTRY_CHANNEL")
            .setContentTitle(title)
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_secure)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
            
        notificationManager.notify(title.hashCode(), notification)
        
        // Add to the tactical queue
        val newAlert = TacticalAlert(title, message)
        alertQueue.add(newAlert)
        
        viewModelScope.launch {
            delay(4500) // Slightly longer to allow for animations
            alertQueue.remove(newAlert)
        }
        
        logSys("ALERT: $title - $message")
    }

    override fun onCleared() {
        super.onCleared()
        signalIntel.stopMagneticScan()
        signalIntel.stopAcousticAnalysis()
        signalIntel.stopJammer()
        networkScanJob?.cancel()
        bleScanJob?.cancel()
    }
}
