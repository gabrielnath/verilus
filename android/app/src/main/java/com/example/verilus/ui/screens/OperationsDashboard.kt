package com.example.verilus.ui.screens

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.provider.Settings
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import androidx.compose.ui.platform.LocalContext
import com.example.verilus.services.SurveillanceService
import com.example.verilus.ui.components.SentryButton
import com.example.verilus.ui.components.ThreatItem
import com.example.verilus.ui.theme.*
import com.example.verilus.util.SentryLogger
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.Locale

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun OperationsDashboard(
    onStartClick: () -> Unit,
    onStopClick: () -> Unit
) {
    // Derived from the service StateFlow — survives screen rotation and reflects actual service state.
    val isRunning by SurveillanceService.isRunning.collectAsState()
    var isNetworkScanning by remember { mutableStateOf(false) }
    var isBleScanning by remember { mutableStateOf(false) }
    var selectedTab by remember { mutableIntStateOf(0) } // 0: Live, 1: Log

    val coroutineScope = rememberCoroutineScope()
    val threats = remember { mutableStateListOf<veriluscore.Threat>() }
    val logEvents by SentryLogger.events.collectAsState(initial = "Initializing Verilus Engine...")
    val consoleLogs = remember { mutableStateListOf<String>() }
    // Stored so the scan coroutine can be cancelled on stop or disposal.
    var networkScanJob by remember { mutableStateOf<Job?>(null) }

    // D-4: Monitor BLE adapter state in real time using a system BroadcastReceiver.
    val context = LocalContext.current
    var isBleSupported by remember { mutableStateOf(true) }
    var isBleEnabled by remember { mutableStateOf(true) }
    DisposableEffect(context) {
        val bluetoothManager = context.getSystemService(BluetoothManager::class.java)
        val adapter = bluetoothManager?.adapter
        isBleSupported = adapter != null
        isBleEnabled = adapter?.isEnabled == true

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                    val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                    isBleEnabled = state == BluetoothAdapter.STATE_ON
                }
            }
        }
        context.registerReceiver(receiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
        onDispose { context.unregisterReceiver(receiver) }
    }

    // Accumulate logs
    LaunchedEffect(logEvents) {
        if (logEvents.isNotEmpty()) {
            consoleLogs.add(0, logEvents)
            if (consoleLogs.size > 50) consoleLogs.removeAt(50)
        }
    }

    // Subscribe to real threat events
    LaunchedEffect(Unit) {
        SurveillanceService.threatEvents.collect { threat ->
            // Filter only if the exact physical device (MAC/IP) is already present
            val isDuplicate = threats.any { 
                (threat.mac.isNotEmpty() && it.mac == threat.mac) || 
                (threat.ip.isNotEmpty() && it.ip == threat.ip) 
            }
            if (!isDuplicate) {
                threats.add(0, threat)
            }
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = VerilusNeutral
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // Header
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 32.dp, start = 24.dp, end = 24.dp, bottom = 20.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "VERILUS",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.Bold,
                                letterSpacing = (-0.5).sp,
                                fontSize = 20.sp
                            ),
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        TextButton(
                            onClick = { threats.clear() },
                            contentPadding = PaddingValues(0.dp),
                            modifier = Modifier.height(24.dp)
                        ) {
                            Text(
                                "RESET",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 10.sp,
                                    letterSpacing = 1.sp
                                ),
                                color = VerilusSageDark
                            )
                        }
                    }
                    
                    Surface(
                        modifier = Modifier.clip(RoundedCornerShape(100.dp)),
                        color = SurfaceSubtle
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(if (isRunning || isBleScanning || isNetworkScanning) VerilusSageDark else TextSecondary, androidx.compose.foundation.shape.CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (isRunning || isBleScanning || isNetworkScanning) "Environment Active" else "System Idle",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp
                                ),
                                color = TextSecondary
                            )
                        }
                    }
                }
            }

            HorizontalDivider(color = BorderSubtle, thickness = 1.dp)

            // D-4: BLE Hardware Warning Banner
            if (!isBleSupported || !isBleEnabled) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    color = VerilusWarning.copy(alpha = 0.08f)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (!isBleSupported) return@clickable
                                context.startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                            }
                            .padding(horizontal = 24.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            imageVector = if (isBleSupported) Icons.Default.BluetoothDisabled else Icons.Default.ErrorOutline,
                            contentDescription = "Bluetooth warning",
                            tint = VerilusWarning,
                            modifier = Modifier.size(18.dp)
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (isBleSupported) "Bluetooth Is Disabled" else "Bluetooth Not Supported",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 11.sp
                                ),
                                color = VerilusWarning
                            )
                            Text(
                                text = if (isBleSupported) "BLE scanning requires Bluetooth. Tap to enable." else "This device cannot scan for BLE threats.",
                                style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                                color = TextSecondary
                            )
                        }
                        if (isBleSupported) {
                            Icon(
                                imageVector = Icons.Default.ChevronRight,
                                contentDescription = null,
                                tint = TextSecondary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
                HorizontalDivider(color = BorderSubtle, thickness = 1.dp)
            }

            // Hero Data
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 16.dp)
            ) {
                Text(
                    text = String.format(Locale.getDefault(), "%02d", threats.size),
                    style = MaterialTheme.typography.displayLarge.copy(
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 58.sp,
                        lineHeight = 58.sp
                    ),
                    color = TextPrimary
                )
                Text(
                    text = "Signals discovered in range",
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontWeight = FontWeight.Medium,
                        fontSize = 14.sp
                    ),
                    color = TextSecondary
                )
            }

            // Action Grid
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 24.dp, end = 24.dp, bottom = 24.dp)
            ) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    SentryButton(
                        text = if (isNetworkScanning) "Scanning..." else "Network Scan",
                        onClick = {
                            if (isNetworkScanning) return@SentryButton
                            isNetworkScanning = true
                            networkScanJob = coroutineScope.launch {
                                delay(1500)
                                try { com.example.verilus.network.NetworkSniffer().scanLocalNetwork() }
                                finally { isNetworkScanning = false }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        icon = Icons.Default.Wifi,
                        useCardStyle = true
                    )
                    SentryButton(
                        text = if (isRunning) "Stop Scan" else "Active Scan",
                        onClick = {
                            if (!isBleEnabled || !isBleSupported) return@SentryButton
                            if (isRunning) {
                                networkScanJob?.cancel()
                                onStopClick()
                            } else {
                                isBleScanning = true
                                coroutineScope.launch {
                                    delay(1500)
                                    onStartClick()
                                    isBleScanning = false
                                }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        icon = if (!isBleEnabled || !isBleSupported) Icons.Default.BluetoothDisabled else Icons.Default.Bluetooth,
                        useCardStyle = true,
                        containerColor = when {
                            !isBleEnabled || !isBleSupported -> SurfaceSubtle
                            isRunning -> Color(0xFFFFF0F0)
                            else -> null
                        },
                        contentColor = when {
                            !isBleEnabled || !isBleSupported -> TextSecondary
                            isRunning -> VerilusDanger
                            else -> null
                        },
                        iconColor = when {
                            !isBleEnabled || !isBleSupported -> TextSecondary
                            isRunning -> VerilusDanger
                            else -> null
                        }
                    )
                }
                // System Integrity Test removed — re-enable when feature is implemented.
                // Never ship a non-functional button to market.
                
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = VerilusSageDark,
                        modifier = Modifier.size(12.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "All signal analysis is performed locally and remains private.",
                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                        color = TextSecondary
                    )
                }
            }

            // List Section
            Surface(
                modifier = Modifier.weight(1f),
                color = Color(0xFFFCFCFC),
                border = BorderStroke(1.dp, BorderSubtle)
            ) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(24.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "DISCOVERED HARDWARE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.5.sp,
                                fontSize = 12.sp
                            ),
                            color = TextSecondary
                        )

                        // Compact Mode Switcher
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .background(SurfaceSubtle, RoundedCornerShape(100.dp))
                                .padding(2.dp)
                        ) {
                            listOf("LIVE", "LOG").forEachIndexed { index, title ->
                                val isSelected = selectedTab == index
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(100.dp))
                                        .background(if (isSelected) Color.White else Color.Transparent)
                                        .clickable { selectedTab = index }
                                        .padding(horizontal = 12.dp, vertical = 4.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = title,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Bold,
                                            fontSize = 9.sp
                                        ),
                                        color = if (isSelected) TextPrimary else TextSecondary
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    if (selectedTab == 0) {
                        // LIVE VIEW
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.spacedBy(14.dp),
                            contentPadding = PaddingValues(bottom = 24.dp)
                        ) {
                            if (isNetworkScanning || isBleScanning) {
                                item {
                                    ThreatItem(
                                        category = "Filtering noise...",
                                        distance = 0.0,
                                        severity = 1,
                                        modifier = Modifier.background(Color.White)
                                    )
                                }
                            }
                            
                            if (threats.isEmpty() && !isNetworkScanning && !isBleScanning) {
                                item {
                                    Box(
                                        modifier = Modifier.fillMaxWidth().height(140.dp),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                            Icon(
                                                Icons.Default.Shield,
                                                contentDescription = null,
                                                tint = SurfaceSubtle,
                                                modifier = Modifier.size(48.dp)
                                            )
                                            Spacer(modifier = Modifier.height(12.dp))
                                            Text(
                                                text = "Surroundings Secure",
                                                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                                                color = TextSecondary
                                            )
                                            Text(
                                                text = "No unauthorized signals found.",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = TextSecondary
                                            )
                                        }
                                    }
                                }
                            } else {
                                items(
                                    items = threats,
                                    key = { "${it.category}-${it.mac}-${it.ip}" }
                                ) { threat ->
                                    ThreatItem(
                                        category = threat.category,
                                        distance = threat.distance,
                                        severity = threat.severity.toInt(),
                                        confidence = threat.confidence,
                                        brand = threat.brand,
                                        ip = threat.ip,
                                        mac = threat.mac,
                                        profile = threat.profile,
                                        modifier = Modifier.animateItem(
                                            fadeInSpec = tween(500),
                                            fadeOutSpec = tween(500),
                                            placementSpec = tween(500)
                                        )
                                    )
                                }
                            }
                        }
                    } else {
                        // LOG VIEW
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(Color(0xFF0A0A0A), RoundedCornerShape(12.dp))
                                .padding(12.dp)
                        ) {
                            LazyColumn(modifier = Modifier.fillMaxSize()) {
                                items(consoleLogs) { log ->
                                    Text(
                                        text = log,
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                            fontSize = 9.sp,
                                            lineHeight = 12.sp
                                        ),
                                        color = Color(0xFF00FF41).copy(alpha = 0.8f),
                                        modifier = Modifier.padding(vertical = 2.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
