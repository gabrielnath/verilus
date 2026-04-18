package com.example.verilus.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import veriluscore.Veriluscore
import java.net.InetSocketAddress
import java.net.Socket

/**
 * NetworkSniffer natively scans the local 802.11 subnet utilizing
 * highly concurrent Kotlin Coroutines to ping IP cameras (RTSP/ONVIF).
 *
 * Separation of network connection I/O (Kotlin) from
 * Threat Assessment Logic (Go Core).
 */
class NetworkSniffer {

    companion object {
        private const val TAG = "NetworkSniffer"
        private const val TIMEOUT_MS = 250 // Aggressive timeout for fast subnet sweeping
        private val TARGET_PORTS = listOf(554, 3702) // RTSP, ONVIF
    }

    /**
     * Executes a massive parallel scan across the /24 subnet natively.
     */
    suspend fun scanLocalNetwork() {
        val baseIp = getLocalSubnetBase() ?: run {
            Log.e(TAG, "Not connected to Wi-Fi. Cannot scan subnet.")
            return
        }

        Log.i(TAG, "Initializing Subnet Sweep on: $baseIp.0/24")

        withContext(Dispatchers.IO) {
            // Generate a massive pool of concurrent coroutines (254 IPs)
            val deferredTasks = (1..254).map { host ->
                async {
                    val targetIp = "$baseIp.$host"
                    val (hasRTSP, hasONVIF) = scanPorts(targetIp)
                    
                    // For modern Android (11+), ARP reads are heavily locked down.
                    // A true production app relies on MDNS/Bonjour or
                    // rooted access for reliable MACs. Pass a stub MAC unless found.
                    val macAddress = resolveARP(targetIp)

                    if (hasRTSP || hasONVIF || macAddress != "00:00:00:00:00:00") {
                        // Pass native hardware socket results down to Go logic core
                        // Pack the IP into the MAC string to maintain AAR binary compatibility
                        val threat = Veriluscore.analyzeNetwork("$macAddress;$targetIp", hasRTSP, hasONVIF)
                        
                        if (threat != null && threat.category != "Unknown") {
                           Log.w(TAG, "🚨 NETWORK THREAT DETECTED -> IP: $targetIp MAC: $macAddress | Threat: ${threat.category} (Severity: ${threat.severity})")
                        }
                    }
                }
            }
            
            // Await all parallel sweeps
            deferredTasks.awaitAll()
            Log.i(TAG, "Subnet Sweep Complete.")
        }
    }

    private fun scanPorts(ip: String): Pair<Boolean, Boolean> {
        var hasRTSP = false
        var hasONVIF = false

        for (port in TARGET_PORTS) {
            try {
                val socket = Socket()
                // Synchronous blocking call executed strictly within Dispatchers.IO
                socket.connect(InetSocketAddress(ip, port), TIMEOUT_MS)
                
                if (port == 554) hasRTSP = true
                if (port == 3702) hasONVIF = true
                
                socket.close()
            } catch (_: Exception) {
                // Connection refused or timeout
            }
        }
        return Pair(hasRTSP, hasONVIF)
    }

    /**
     * Approximates the device's current Wi-Fi sub-network.
     */
    private fun getLocalSubnetBase(): String? {
        try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            for (intf in interfaces) {
                if (intf.isLoopback || !intf.isUp) continue
                for (addr in intf.inetAddresses) {
                    if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                        val ip = addr.hostAddress ?: continue
                        // Filter for common private local networks
                        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
                            val parts = ip.split(".")
                            if (parts.size == 4) return "${parts[0]}.${parts[1]}.${parts[2]}"
                        }
                    }
                }
            }
        } catch (_: Exception) {
            Log.e(TAG, "Error resolving local IP address interfaces.")
        }
        return null
    }

    /**
     * Best-effort ARP resolution for identifying MAC addresses physically.
     * Note: Android 11+ deliberately breaks reading /proc/net/arp for privacy.
     */
    private fun resolveARP(ip: String): String {
        try {
            val br = java.io.BufferedReader(java.io.FileReader("/proc/net/arp"))
            var line: String?
            while (br.readLine().also { line = it } != null) {
                val splitted = line!!.split(" +".toRegex()).toTypedArray()
                if (splitted.size >= 4 && ip == splitted[0]) {
                    val mac = splitted[3]
                    if (mac.matches(Regex("..:..:..:..:..:.."))) {
                        return mac
                    }
                }
            }
            br.close()
        } catch (_: Exception) {
            // ARP read denied or file not accessible
        }
        return "00:00:00:00:00:00"
    }
}
