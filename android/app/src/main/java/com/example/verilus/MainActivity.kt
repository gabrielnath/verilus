package com.example.verilus

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import com.example.verilus.services.SurveillanceService
import com.example.verilus.ui.screens.OperationsDashboard
import com.example.verilus.ui.theme.VerilusTheme

class MainActivity : ComponentActivity() {

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val allGranted = results.values.all { it }
        if (!allGranted) {
            // Inform the user that degraded functionality will result
            Toast.makeText(
                this,
                "Bluetooth & Location permissions are required for threat detection.",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        requestNecessaryPermissions()

        setContent {
            VerilusTheme {
                OperationsDashboard(
                    onStartClick = { toggleService(true) },
                    onStopClick = { toggleService(false) }
                )
            }
        }
    }

    /**
     * Toggles the SurveillanceService.
     * IMPORTANT: startForegroundService() must ONLY be called when starting.
     * Calling it for a stop action causes an ANR crash on Android 14+ because
     * the service receives ACTION_STOP and never calls startForeground().
     */
    private fun toggleService(start: Boolean) {
        val intent = Intent(this, SurveillanceService::class.java).apply {
            action = if (start) SurveillanceService.ACTION_START else SurveillanceService.ACTION_STOP
        }
        if (start) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun requestNecessaryPermissions() {
        val permissionsToRequest = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissionsToRequest.add(Manifest.permission.BLUETOOTH_SCAN)
            permissionsToRequest.add(Manifest.permission.BLUETOOTH_CONNECT)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissionsToRequest.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        permissionLauncher.launch(permissionsToRequest.toTypedArray())
    }
}