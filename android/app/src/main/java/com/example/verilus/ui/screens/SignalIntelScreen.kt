package com.example.verilus.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.verilus.ui.components.SentryButton
import com.example.verilus.ui.theme.*
import com.example.verilus.util.SignalIntelligence
import veriluscore.SignalResult
import kotlin.math.roundToInt

@Composable
fun SignalIntelScreen(
    magLevel: Float,
    magBaseline: Float,
    magResult: SignalResult?,
    acousticAlert: Boolean,
    isJamming: Boolean,
    selectedMode: SignalIntelligence.JamMode,
    onModeChange: (SignalIntelligence.JamMode) -> Unit,
    onJamToggle: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // --- Magnetic Section ---
        MagneticMonitorCard(magLevel, magBaseline, magResult)

        // --- Acoustic Section ---
        AcousticStatusCard(acousticAlert)

        // --- ECM Section ---
        CountermeasuresControls(
            isJamming = isJamming,
            selectedMode = selectedMode,
            onModeChange = onModeChange,
            onJamToggle = onJamToggle
        )
    }
}

@Composable
private fun MagneticMonitorCard(level: Float, baseline: Float, result: SignalResult?) {
    val isThreat = result?.hasThreat == true
    val delta = (level - baseline) // Can be negative now
    
    // Tactical Gap Calibration:
    // Red: Spike > 60 uT (confirmed anomaly)
    // Yellow: Spike > 20 uT (proximity warning)
    val statusColor = when {
        (isThreat && delta > 20f) || delta > 60f -> VerilusDanger
        delta > 20f -> VerilusWarning
        else -> TextPrimary
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = if (isThreat) statusColor.copy(alpha = 0.05f) else SurfaceSubtle),
        border = BorderStroke(1.dp, if (isThreat) statusColor.copy(alpha = 0.5f) else BorderSubtle)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), Arrangement.SpaceBetween, Alignment.CenterVertically) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Default.Cable, null, tint = statusColor, modifier = Modifier.size(14.dp))
                    Text("Magnetic Field Monitor", style = MaterialTheme.typography.labelMedium, color = statusColor)
                }
                if (statusColor != TextPrimary) {
                    StatusBadge("ANOMALY", statusColor)
                }
            }
            Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxWidth().height(60.dp)) {
                Text("${level.roundToInt()} μT", style = MaterialTheme.typography.headlineMedium.copy(fontWeight = FontWeight.Black), color = statusColor)
            }
            Text(
                result?.info ?: "Scanning for hidden electronics...",
                style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold),
                color = if (isThreat) statusColor else TextSecondary,
                lineHeight = 12.sp
            )
        }
    }
}

@Composable
private fun AcousticStatusCard(isAlert: Boolean) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = if (isAlert) VerilusDanger.copy(alpha = 0.1f) else SurfaceSubtle),
        border = BorderStroke(1.dp, if (isAlert) VerilusDanger else BorderSubtle)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(Modifier.size(40.dp).clip(CircleShape).background(if (isAlert) VerilusDanger.copy(alpha = 0.2f) else BorderSubtle), Alignment.Center) {
                Icon(if (isAlert) Icons.Default.Warning else Icons.Default.Hearing, null, tint = if (isAlert) VerilusDanger else TextSecondary, modifier = Modifier.size(18.dp))
            }
            Column {
                Text(if (isAlert) "Ultrasonic Threat Detected" else "Acoustic Environment Safe", style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold, fontSize = 11.sp), color = if (isAlert) VerilusDanger else TextPrimary)
                Text(if (isAlert) "High-frequency beacon match found." else "No hidden data exfiltration detected.", style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp), color = TextSecondary)
            }
        }
    }
}

@Composable
private fun CountermeasuresControls(
    isJamming: Boolean,
    selectedMode: SignalIntelligence.JamMode,
    onModeChange: (SignalIntelligence.JamMode) -> Unit,
    onJamToggle: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Electronic Countermeasures (ECM)", style = MaterialTheme.typography.labelMedium.copy(fontSize = 11.sp, fontWeight = FontWeight.Bold), color = TextPrimary)
        
        Row(Modifier.fillMaxWidth().background(SurfaceSubtle, RoundedCornerShape(12.dp)).padding(4.dp), Arrangement.spacedBy(4.dp)) {
            SignalIntelligence.JamMode.entries.forEach { mode ->
                val isSelected = selectedMode == mode
                Box(Modifier.weight(1f).clip(RoundedCornerShape(8.dp)).background(if (isSelected) Color.White else Color.Transparent).clickable { onModeChange(mode) }.padding(vertical = 8.dp), Alignment.Center) {
                    Text(
                        when(mode) {
                            SignalIntelligence.JamMode.ULTRASONIC_SWEEP -> "ULTRASONIC"
                            SignalIntelligence.JamMode.WHITE_NOISE_MASK -> "AUDIO"
                            SignalIntelligence.JamMode.KINETIC_GLASS_MASHER -> "GLASS"
                        },
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Bold, fontSize = 10.sp),
                        color = if (isSelected) TextPrimary else TextSecondary
                    )
                }
            }
        }
        
        SentryButton(
            text = if (isJamming) "Deactivate Countermeasures" else "Initialize Jammer",
            onClick = onJamToggle,
            modifier = Modifier.fillMaxWidth(),
            icon = if (isJamming) Icons.Default.PowerSettingsNew else Icons.Default.Stream,
            useCardStyle = true,
            iconSideBySide = true,
            containerColor = if (isJamming) Color(0xFFFFF0F0) else null,
            contentColor = if (isJamming) VerilusDanger else null,
            iconColor = if (isJamming) VerilusDanger else null
        )
        
        Text(
            when(selectedMode) {
                SignalIntelligence.JamMode.ULTRASONIC_SWEEP -> "Sweeps 18kHz-22kHz to disrupt covert ultrasonic communications and tracking beacons."
                SignalIntelligence.JamMode.WHITE_NOISE_MASK -> "Emits randomized white noise to interfere with nearby hidden voice recording hardware."
                SignalIntelligence.JamMode.KINETIC_GLASS_MASHER -> "Vibrates the phone against window glass to neutralize external laser microphones."
            },
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp), color = TextSecondary, lineHeight = 12.sp
        )
    }
}

@Composable
private fun StatusBadge(text: String, color: Color) {
    Surface(color = color, shape = RoundedCornerShape(4.dp)) {
        Text(text, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp), style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Black, fontSize = 8.sp), color = Color.White)
    }
}
