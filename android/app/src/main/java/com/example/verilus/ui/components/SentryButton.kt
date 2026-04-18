package com.example.verilus.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.verilus.ui.theme.*

@Composable
fun SentryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    isFullWidth: Boolean = false,
    useCardStyle: Boolean = false,
    containerColor: Color? = null,
    contentColor: Color? = null,
    iconColor: Color? = null
) {
    val finalContainerColor = containerColor ?: if (isFullWidth) TextPrimary else SurfaceSubtle
    val finalContentColor = contentColor ?: if (isFullWidth) Color.White else TextPrimary
    val finalIconColor = iconColor ?: if (isFullWidth) VerilusSage else VerilusSageDark

    Surface(
        onClick = onClick,
        modifier = modifier
            .fillMaxWidth()
            .then(if (useCardStyle) Modifier.height(100.dp) else Modifier.height(60.dp)),
        shape = RoundedCornerShape(20.dp),
        color = finalContainerColor,
        border = if (!isFullWidth) BorderStroke(1.dp, BorderSubtle) else null
    ) {
        if (useCardStyle) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.Center
            ) {
                if (icon != null) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = finalIconColor,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                }
                Text(
                    text = text,
                    style = MaterialTheme.typography.bodyLarge.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    ),
                    color = finalContentColor
                )
            }
        } else {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = if (isFullWidth) Arrangement.SpaceBetween else Arrangement.Center,
                modifier = Modifier.padding(horizontal = 24.dp)
            ) {
                Text(
                    text = text,
                    style = MaterialTheme.typography.bodyLarge.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    ),
                    color = finalContentColor
                )
                if (icon != null) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = finalIconColor,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        }
    }
}


