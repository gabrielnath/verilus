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
    brand: String = "",
    ip: String = "",
    mac: String = ""
) {
    val isSevere = severity >= 4
    
    // Formatted details are remembered to prevent re-calculation during scroll
    val forensicDetails = remember(ip, mac) {
        listOfNotNull(
            if (ip.isNotEmpty()) "IP: $ip" else null,
            if (mac.isNotEmpty() && mac != "00:00:00:00:00:00") "MAC: $mac" else null
        ).joinToString("  |  ")
    }
    
    val proximityText = remember(distance) {
        if (distance > 0) String.format(Locale.getDefault(), "PROXIMITY: %.1f METERS", distance) else ""
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .graphicsLayer { // Offload to GPU for idk just trying smooth scrolling
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
        }

        // Tag
        Box(
            modifier = Modifier
                .background(
                    if (isSevere) Color(0xFFFFF0F0) else SurfaceSubtle,
                    RoundedCornerShape(6.dp)
                )
                .padding(horizontal = 8.dp, vertical = 4.dp)
        ) {
            Text(
                text = if (isSevere) "THREAT" else if (severity > 0) "ACTIVE" else "SECURE",
                style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 10.sp
                ),
                color = if (isSevere) VerilusDanger else if (severity > 0) VerilusSageDark else TextSecondary
            )
        }
    }
}





