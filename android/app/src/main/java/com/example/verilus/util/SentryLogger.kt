package com.example.verilus.util

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.text.SimpleDateFormat
import java.util.*

/**
 * Global forensic logger for real-time hardware activity.
 */
object SentryLogger {
    private val _events = MutableSharedFlow<String>(replay = 50, extraBufferCapacity = 50)
    val events = _events.asSharedFlow()

    fun log(message: String) {
        val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
        val timestamp = timeFormat.format(Date())
        _events.tryEmit("[$timestamp] $message")
    }
}
