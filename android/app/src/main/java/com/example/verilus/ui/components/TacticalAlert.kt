package com.example.verilus.ui.components

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.verilus.ui.theme.*
import com.example.verilus.viewmodels.TacticalAlert

@Composable
fun TacticalAlertOverlay(
    alerts: List<TacticalAlert>,
    onDismiss: (TacticalAlert) -> Unit
) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .padding(top = 64.dp)
                .widthIn(max = 400.dp)
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            alerts.forEach { alert ->
                key(alert.id) {
                    TacticalPillAlert(
                        title = alert.title,
                        message = alert.message,
                        onDismiss = { onDismiss(alert) }
                    )
                }
            }
        }
    }
}

@Composable
private fun TacticalPillAlert(
    title: String,
    message: String,
    onDismiss: () -> Unit
) {
    // New Minimalist Pill Design: Focus on precision and stealth
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 72.dp, max = 96.dp), // Increased height for multi-line support
        shape = RoundedCornerShape(24.dp), // More elegant "stadium" card instead of pure pill
        color = VerilusNeutral,
        border = BorderStroke(1.dp, BorderSubtle),
        shadowElevation = 2.dp,
        onClick = onDismiss
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            // Left-edge Status strip (Tactical identity)
            Box(
                modifier = Modifier
                    .width(6.dp)
                    .fillMaxHeight()
                    .background(VerilusSageDark)
                    .align(Alignment.CenterStart)
            )

            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(start = 22.dp, end = 20.dp, top = 12.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Minimal icon
                Icon(
                    imageVector = Icons.Default.NotificationsActive,
                    contentDescription = null,
                    tint = VerilusSageDark,
                    modifier = Modifier.size(20.dp)
                )

                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.ExtraBold,
                                letterSpacing = 0.5.sp,
                                fontSize = 11.sp
                            ),
                            color = VerilusSageDark
                        )
                        Box(Modifier.size(3.dp).background(TextSecondary.copy(alpha = 0.4f), CircleShape))
                        Text(
                            text = "ACTIVE",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp
                            ),
                            color = VerilusSageDark.copy(alpha = 0.7f)
                        )
                    }
                    Text(
                        text = message,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontWeight = FontWeight.Medium,
                            fontSize = 12.sp,
                            lineHeight = 16.sp, // Added line height for multi-line comfort
                            color = TextPrimary
                        ),
                        maxLines = 2, // Allow more text to prevent cropping
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                }
            }

            // Subtle feedback line (bottom)
            var progress by remember { mutableFloatStateOf(1f) }
            val animatedProgress by animateFloatAsState(
                targetValue = progress,
                animationSpec = tween(durationMillis = 4000, easing = LinearEasing),
                label = "AlertProgress"
            )

            LaunchedEffect(Unit) {
                progress = 0f
            }

            LinearProgressIndicator(
                progress = { animatedProgress },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(horizontal = 32.dp) // Inset for a "floating" feel
                    .fillMaxWidth()
                    .height(1.5.dp),
                color = VerilusSage.copy(alpha = 0.6f),
                trackColor = Color.Transparent,
                strokeCap = androidx.compose.ui.graphics.StrokeCap.Round
            )
        }
    }
}
