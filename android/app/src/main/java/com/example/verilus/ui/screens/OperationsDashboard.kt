package com.example.verilus.ui.screens

import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.provider.Settings
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.verilus.ui.components.SentryButton
import com.example.verilus.ui.components.TacticalAlertOverlay
import com.example.verilus.ui.theme.*
import com.example.verilus.viewmodels.DashboardViewModel
import java.util.Locale

@Composable
fun OperationsDashboard(
    onStartClick: () -> Unit,
    onStopClick: () -> Unit,
    vm: DashboardViewModel = viewModel()
) {
    val context = LocalContext.current
    val isRunning by vm.isRunning.collectAsState()
    
    // Hardware State Listeners
    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                    val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                    vm.isBleEnabled = state == BluetoothAdapter.STATE_ON
                }
            }
        }
        context.registerReceiver(receiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
        onDispose { context.unregisterReceiver(receiver) }
    }

    // Passive forensic monitors activation
    LaunchedEffect(Unit) {
        vm.startMonitors()
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = VerilusNeutral
        ) { innerPadding ->
            Column(Modifier.fillMaxSize().padding(innerPadding)) {
                // Header with Reset button
                DashboardHeader(
                    isRunning = isRunning || vm.isBleScanning || vm.isNetworkScanning,
                    onReset = { vm.clearThreats() }
                )
                
                HorizontalDivider(color = BorderSubtle, thickness = 1.dp)

                if (!vm.isBleSupported || !vm.isBleEnabled) {
                    BluetoothWarningBanner(context, vm.isBleSupported)
                    HorizontalDivider(color = BorderSubtle, thickness = 1.dp)
                }

                HeroSection(threatCount = vm.threats.size)
                
                ActionGrid(
                    isRunning = isRunning,
                    isNetworkScanning = vm.isNetworkScanning,
                    isBleSupported = vm.isBleSupported,
                    isBleEnabled = vm.isBleEnabled,
                    onNetworkClick = { vm.startNetworkScan() },
                    onBleToggle = { vm.toggleBleScan(onStartClick, onStopClick) }
                )

                // Content Area with Tab Switching
                Surface(modifier = Modifier.weight(1f), color = Color(0xFFFCFCFC), border = BorderStroke(1.dp, BorderSubtle)) {
                    MainContentArea(vm)
                }
            }
        }
        
        // High-fidelity Tactical Alert Stack
        if (vm.alertQueue.isNotEmpty()) {
            TacticalAlertOverlay(
                alerts = vm.alertQueue,
                onDismiss = { alert -> vm.alertQueue.remove(alert) }
            )
        }
    }
}

@Composable
private fun DashboardHeader(isRunning: Boolean, onReset: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(top = 32.dp, start = 24.dp, end = 24.dp, bottom = 20.dp)) {
        Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween, Alignment.CenterVertically) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("VERILUS", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp, fontSize = 20.sp), color = TextPrimary)
                Spacer(Modifier.width(12.dp))
                TextButton(onClick = onReset, contentPadding = PaddingValues(0.dp), modifier = Modifier.height(24.dp)) {
                    Text("RESET", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.ExtraBold, fontSize = 10.sp, letterSpacing = 1.sp), color = VerilusSageDark)
                }
            }
            
            StatusIndicator(isActive = isRunning)
        }
    }
}

@Composable
private fun HeroSection(threatCount: Int) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp)) {
        Text(String.format(Locale.getDefault(), "%02d", threatCount), 
             style = MaterialTheme.typography.displayLarge.copy(fontWeight = FontWeight.ExtraBold, fontSize = 58.sp, lineHeight = 58.sp), color = TextPrimary)
        Text("Signals discovered in range", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium, fontSize = 14.sp), color = TextSecondary)
    }
}

@Composable
private fun ActionGrid(
    isRunning: Boolean,
    isNetworkScanning: Boolean,
    isBleSupported: Boolean,
    isBleEnabled: Boolean,
    onNetworkClick: () -> Unit,
    onBleToggle: () -> Unit
) {
    Column(Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, bottom = 24.dp)) {
        Row(Modifier.fillMaxWidth(), Arrangement.spacedBy(12.dp), Alignment.CenterVertically) {
            SentryButton(
                text = if (isNetworkScanning) "Scanning..." else "Network Scan", 
                onClick = onNetworkClick, 
                modifier = Modifier.weight(1f), 
                icon = Icons.Default.Wifi, 
                useCardStyle = true,
            )
            SentryButton(
                text = if (isRunning) "Stop Scan" else "Active Scan", 
                onClick = onBleToggle, 
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
        Spacer(Modifier.height(16.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Lock, null, tint = VerilusSageDark, modifier = Modifier.size(12.dp))
            Spacer(Modifier.width(6.dp))
            Text("All signal analysis is performed locally and remains private.", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp), color = TextSecondary)
        }
    }
}

@Composable
private fun MainContentArea(vm: DashboardViewModel) {
    Column(Modifier.padding(24.dp)) {
        TabSwitcher(selectedIndex = vm.selectedTab, onTabClick = { vm.setTab(it) })
        Spacer(Modifier.height(16.dp))

        when (vm.selectedTab) {
            0 -> LiveThreatScreen(vm.threats, vm.isNetworkScanning || vm.isBleScanning)
            1 -> {
                val magLevel by vm.magLevel.collectAsState()
                val magBaseline by vm.magBaseline.collectAsState()
                val magResult by vm.magResult.collectAsState()
                val acousticAlert by vm.acousticAlert.collectAsState()
                
                SignalIntelScreen(
                    magLevel = magLevel,
                    magBaseline = magBaseline,
                    magResult = magResult,
                    acousticAlert = acousticAlert,
                    isJamming = vm.isJamming,
                    selectedMode = vm.jamMode,
                    onModeChange = { vm.updateJamMode(it) },
                    onJamToggle = { vm.toggleJammer() }
                )
            }
            2 -> ConsoleLogScreen(vm.consoleLogs)
        }
    }
}

@Composable
private fun TabSwitcher(selectedIndex: Int, onTabClick: (Int) -> Unit) {
    Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween, Alignment.CenterVertically) {
        Text("DISCOVERED HARDWARE", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 0.5.sp, fontSize = 12.sp), color = TextSecondary)
        Row(Modifier.background(SurfaceSubtle, RoundedCornerShape(100.dp)).padding(2.dp)) {
            listOf("LIVE", "SIG", "LOG").forEachIndexed { index, title ->
                val isSelected = selectedIndex == index
                Box(Modifier.clip(RoundedCornerShape(100.dp)).background(if (isSelected) Color.White else Color.Transparent).clickable { onTabClick(index) }.padding(horizontal = 12.dp, vertical = 4.dp)) {
                    Text(title, style = MaterialTheme.typography.labelSmall.copy(fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Bold, fontSize = 9.sp), color = if (isSelected) TextPrimary else TextSecondary)
                }
            }
        }
    }
}

@Composable
private fun ConsoleLogScreen(logs: List<String>) {
    Box(Modifier.fillMaxSize().background(Color(0xFF0A0A0A), RoundedCornerShape(12.dp)).padding(12.dp)) {
        LazyColumn(Modifier.fillMaxSize()) {
            items(logs) { log ->
                Text(log, style = MaterialTheme.typography.bodySmall.copy(fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontSize = 9.sp, lineHeight = 12.sp), color = Color(0xFF00FF41).copy(alpha = 0.8f))
            }
        }
    }
}

@Composable
private fun StatusIndicator(isActive: Boolean) {
    Surface(Modifier.clip(RoundedCornerShape(100.dp)), color = SurfaceSubtle) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(Modifier.size(6.dp).background(if (isActive) VerilusSageDark else TextSecondary, CircleShape))
            Text(if (isActive) "Environment Active" else "System Idle", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, fontSize = 11.sp), color = TextSecondary)
        }
    }
}

@Composable
private fun BluetoothWarningBanner(context: Context, isSupported: Boolean) {
    Surface(Modifier.fillMaxWidth(), color = VerilusWarning.copy(alpha = 0.08f)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { if (isSupported) context.startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS)) }
                .padding(horizontal = 24.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(if (isSupported) Icons.Default.BluetoothDisabled else Icons.Default.ErrorOutline, null, tint = VerilusWarning, modifier = Modifier.size(18.dp))
            Column(Modifier.weight(1f)) {
                Text(if (isSupported) "Bluetooth Is Disabled" else "Bluetooth Not Supported", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.ExtraBold, fontSize = 11.sp), color = VerilusWarning)
                Text(if (isSupported) "BLE scanning requires Bluetooth. Tap to enable." else "This device cannot scan for BLE threats.", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp), color = TextSecondary)
            }
            if (isSupported) Icon(Icons.Default.ChevronRight, null, tint = TextSecondary, modifier = Modifier.size(16.dp))
        }
    }
}
