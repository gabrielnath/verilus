package com.example.verilus.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val DarkColorScheme = darkColorScheme(
    primary = VerilusSage,
    secondary = TextSecondary,
    tertiary = VerilusSageDark,
    background = Color(0xFF1A1C1E),
    surface = Color(0xFF2C2E30),
    onPrimary = Color.Black,
    onBackground = Color.White,
    onSurface = Color.White,
    error = VerilusDanger
)

private val LightColorScheme = lightColorScheme(
    primary = VerilusSage,
    secondary = TextSecondary,
    tertiary = VerilusSageDark,
    background = VerilusNeutral,
    surface = VerilusNeutral,
    onPrimary = Color.Black,
    onBackground = TextPrimary,
    onSurface = TextPrimary,
    error = VerilusDanger
)

@Composable
fun VerilusTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}