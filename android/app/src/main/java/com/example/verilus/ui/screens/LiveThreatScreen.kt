package com.example.verilus.ui.screens

import androidx.compose.animation.core.tween
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.tooling.preview.Preview
import com.example.verilus.ui.components.ThreatItem
import com.example.verilus.ui.theme.*
import veriluscore.Threat

/**
 * A preview-safe data class that mirrors the Threat object.
 * This allows the UI to be rendered in Android Studio without loading native GO libraries.
 */
data class ThreatUIState(
    val category: String,
    val distance: Double,
    val severity: Int,
    val confidence: Double,
    val brand: String,
    val ip: String,
    val mac: String,
    val profile: String
)

@Composable
fun LiveThreatScreen(
    threats: List<Threat>,
    isScanning: Boolean
) {
    // Map native Go threats to Preview-safe UI state
    val uiStates = threats.map { 
        ThreatUIState(
            category = it.category,
            distance = it.distance,
            severity = it.severity.toInt(),
            confidence = it.confidence,
            brand = it.brand,
            ip = it.ip,
            mac = it.mac,
            profile = it.profile
        )
    }
    
    LiveThreatContent(uiStates, isScanning)
}

@Composable
fun LiveThreatContent(
    uiStates: List<ThreatUIState>,
    isScanning: Boolean
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        contentPadding = PaddingValues(bottom = 24.dp)
    ) {
        if (isScanning) {
            item {
                ThreatItem(
                    category = "Filtering noise...",
                    distance = 0.0,
                    severity = 1,
                    modifier = Modifier.background(Color.White)
                )
            }
        }
        
        if (uiStates.isEmpty() && !isScanning) {
            item { EmptyThreatState() }
        } else {
            items(
                items = uiStates,
                key = { "${it.category}-${it.mac}-${it.ip}" }
            ) { state ->
                ThreatItem(
                    category = state.category,
                    distance = state.distance,
                    severity = state.severity,
                    confidence = state.confidence,
                    brand = state.brand,
                    ip = state.ip,
                    mac = state.mac,
                    profile = state.profile,
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

@Composable
private fun EmptyThreatState() {
    Box(
        modifier = Modifier.fillMaxWidth().height(140.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.Shield, null, tint = SurfaceSubtle, modifier = Modifier.size(48.dp))
            Spacer(modifier = Modifier.height(12.dp))
            Text("Surroundings Secure", style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold), color = TextSecondary)
            Text("No unauthorized signals found.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
    }
}

@Preview(showBackground = true, backgroundColor = 0xFFFCFCFC)
@Composable
fun LiveThreatScreenPreview() {
    VerilusTheme {
        Box(Modifier.padding(24.dp).fillMaxSize()) {
            LiveThreatContent(
                uiStates = listOf(
                    ThreatUIState("Hidden Camera", 1.2, 3, 0.95, "Sony", "192.168.1.104", "00:1A:XX:XX:XX:01", "SURVEILLANCE"),
                    ThreatUIState("Unknown Beacon", 4.5, 2, 0.85, "Generic", "None", "FF:EE:DD:CC:BB:AA", "BAD_ACTOR"),
                    ThreatUIState("Home Router", 12.0, 1, 0.99, "TP-Link", "192.168.1.1", "AA:BB:CC:DD:EE:FF", "SAFE")
                ),
                isScanning = false
            )
        }
    }
}
