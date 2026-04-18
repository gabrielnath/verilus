package com.example.verilus.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.verilus.ui.theme.*
import java.util.Locale

@Composable
fun ThreatItem(
    modifier: Modifier = Modifier,
    category: String,
    distance: Double,
    severity: Int,
    confidence: Double = 0.0,
    brand: String = "",
    ip: String = "",
    mac: String = "",
    profile: String = "SAFE"
) {
    val isSevere = severity >= 4
    
    // Formatted details are remembered to prevent re-calculation during scroll
    val forensicDetails = remember(ip, mac) {
        listOfNotNull(
            if (ip.isNotEmpty()) "IP: $ip" else null,
            if (mac.isNotEmpty() && mac != "00:00:00:00:00:00") "MAC: $mac" else null
        ).joinToString("  |  ")
    }
    
    val proximityText = remember(distance, confidence) {
        val confPct = (confidence * 100).toInt()
        val confStr = if (confPct > 0) "CONFIDENCE: $confPct%" else ""
        val distStr = if (distance > 0) String.format(Locale.getDefault(), "PROXIMITY: %.1fM", distance) else ""
        
        listOfNotNull(
            distStr.takeIf { it.isNotEmpty() },
            confStr.takeIf { it.isNotEmpty() }
        ).joinToString("  |  ")
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .graphicsLayer { 
                shape = RoundedCornerShape(16.dp)
                clip = true
            }
            .background(Color.White)
            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Icon Circle
        Box(
            modifier = Modifier
                .size(44.dp)
                .background(SurfaceSubtle, RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = when {
                    category.contains("Cam", ignoreCase = true) -> Icons.Default.Videocam 
                    category.contains("Glass", ignoreCase = true) -> Icons.Default.Visibility
                    category.contains("UAV", ignoreCase = true) -> Icons.Default.Flight
                    category.contains("Tracker", ignoreCase = true) -> Icons.Default.LocationOn
                    else -> Icons.Default.Memory
                },
                contentDescription = null,
                tint = TextPrimary,
                modifier = Modifier.size(20.dp)
            )
        }

        Spacer(modifier = Modifier.width(16.dp))

        // Info
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = category.uppercase(Locale.getDefault()),
                    style = MaterialTheme.typography.titleSmall.copy(
                        fontWeight = FontWeight.ExtraBold,
                        letterSpacing = 0.5.sp,
                        fontSize = 13.sp
                    ),
                    color = TextPrimary
                )
                if (brand.isNotEmpty()) {
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "• $brand",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                }
            }
            
            if (forensicDetails.isNotEmpty()) {
                Text(
                    text = forensicDetails,
                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 11.sp),
                    color = TextSecondary
                )
            }

            if (proximityText.isNotEmpty()) {
                Text(
                    text = proximityText,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = 10.sp,
                        letterSpacing = 0.3.sp
                    ),
                    color = if (isSevere) VerilusDanger else VerilusSageDark
                )
            }

            // Disclaimer Footnote
            Text(
                text = "Data is an estimation. False positives may occur.",
                style = MaterialTheme.typography.labelSmall.copy(
                    fontSize = 8.sp,
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
                ),
                color = TextSecondary.copy(alpha = 0.7f)
            )
        }

        // Compact Forensic Badge (THREAT / ACTIVE / SAFE)
        Box(
            modifier = Modifier
                .padding(start = 8.dp)
                .background(
                    color = when (profile) {
                        "BAD_ACTOR" -> VerilusDanger.copy(alpha = 0.1f)
                        "SURVEILLANCE" -> VerilusWarning.copy(alpha = 0.1f)
                        else -> VerilusSage.copy(alpha = 0.1f)
                    },
                    shape = RoundedCornerShape(6.dp)
                )
                .padding(horizontal = 8.dp, vertical = 4.dp)
        ) {
            Text(
                text = when (profile) {
                    "BAD_ACTOR" -> "THREAT"
                    "SURVEILLANCE" -> "ACTIVE"
                    else -> "SAFE"
                },
                style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 10.sp,
                    letterSpacing = 0.5.sp
                ),
                color = when (profile) {
                    "BAD_ACTOR" -> VerilusDanger
                    "SURVEILLANCE" -> VerilusWarning
                    else -> VerilusSageDark
                }
            )
        }
    }
}

@androidx.compose.ui.tooling.preview.Preview(showBackground = true)
@Composable
fun ThreatItemGallery() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFF9FAFB))
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = "FORENSIC UI GALLERY",
            style = MaterialTheme.typography.labelSmall.copy(
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 1.sp
            ),
            color = TextSecondary,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        // 1. THREAT (Red) - AirTag
        ThreatItem(
            category = "AirTag / Tracker",
            distance = 1.2,
            severity = 5,
            confidence = 0.95,
            brand = "Apple, Inc.",
            mac = "3C:D0:F8:11:22:33",
            profile = "BAD_ACTOR"
        )

        // 2. ACTIVE (Orange) - Hikvision
        ThreatItem(
            category = "Network Camera",
            distance = 4.5,
            severity = 3,
            confidence = 0.88,
            brand = "Hikvision",
            ip = "192.168.1.104",
            profile = "SURVEILLANCE"
        )

        // 3. SECURE / IDENTIFIED (Green) - AirPods
        ThreatItem(
            category = "Audio Device",
            distance = 0.8,
            severity = 1,
            confidence = 0.99,
            brand = "Apple, Inc.",
            mac = "0C:75:D2:AA:BB:CC",
            profile = "SAFE"
        )
    }
}
