package com.example.verilus.ui.screens

import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.verilus.services.SurveillanceService
import com.example.verilus.ui.components.SentryButton
import com.example.verilus.ui.components.ThreatItem
import com.example.verilus.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.Locale

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun OperationsDashboard(
    onStartClick: () -> Unit,
    onStopClick: () -> Unit
) {
    var isRunning by remember { mutableStateOf(false) }
    var isNetworkScanning by remember { mutableStateOf(false) }
    var isBleScanning by remember { mutableStateOf(false) }
    
    val coroutineScope = rememberCoroutineScope()
    val threats = remember { mutableStateListOf<veriluscore.Threat>() }

    // Subscribe to real threat events
    LaunchedEffect(Unit) {
        SurveillanceService.threatEvents.collect { threat ->
            if (threats.none { it.category == threat.category }) {
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

            // Hero Data
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 32.dp)
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
                            coroutineScope.launch {
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
                            if (isRunning) {
                                onStopClick()
                                isRunning = false
                            } else {
                                isBleScanning = true
                                coroutineScope.launch {
                                    delay(1500)
                                    onStartClick()
                                    isBleScanning = false
                                    isRunning = true
                                }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        icon = Icons.Default.Bluetooth,
                        useCardStyle = true,
                        containerColor = if (isRunning) Color(0xFFFFF0F0) else null,
                        contentColor = if (isRunning) VerilusDanger else null,
                        iconColor = if (isRunning) VerilusDanger else null
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                SentryButton(
                    text = "System Integrity Test",
                    onClick = {
                        coroutineScope.launch {
                            delay(500)
                            // Simulate raw hardware packets piped through Go Logic
                            val metaPack = byteArrayOf(0x7D.toByte(), 0x02.toByte(), 0x01)
                            val metaThreat = veriluscore.Veriluscore.analyze(metaPack, "FF01;EB:04:1A:66:BD:22", -42)
                            
                            val djiPack = byteArrayOf(0xAA.toByte(), 0x08.toByte())
                            val djiThreat = veriluscore.Veriluscore.analyze(djiPack, "FF6B;D4:8C:81:AA:BB:CC", -75)

                            val tagPack = byteArrayOf(0x4C.toByte(), 0x00.toByte(), 0x12.toByte())
                            val tagThreat = veriluscore.Veriluscore.analyze(tagPack, "FD69;50:D4:F7:11:22:33", -60)

                            val camThreat = veriluscore.Veriluscore.analyzeNetwork("0C:75:D2:11:22:33;192.168.1.104", true, false)

                            listOfNotNull(metaThreat, djiThreat, tagThreat, camThreat).forEach { threat ->
                                if (threat.category != "Unknown" && threats.none { it.category == threat.category }) {
                                    threats.add(0, threat)
                                }
                            }
                        }
                    },
                    icon = Icons.Default.Shield,
                    isFullWidth = true
                )
                
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
                        .fillMaxSize()
                        .padding(24.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
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
                        Text(
                            text = if (isNetworkScanning || isBleScanning) "SCANNING" else "LIVE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            ),
                            color = if (isNetworkScanning || isBleScanning) VerilusWarning else VerilusSageDark
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

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
                                key = { it.category }
                            ) { threat ->
                                ThreatItem(
                                    category = threat.category,
                                    distance = threat.distance,
                                    severity = threat.severity.toInt(),
                                    brand = threat.brand,
                                    ip = threat.ip,
                                    mac = threat.mac,
                                    modifier = Modifier.animateItem(
                                        fadeInSpec = tween(500),
                                        fadeOutSpec = tween(500),
                                        placementSpec = tween(500)
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}



