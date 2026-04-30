package com.example.verilus.util

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Vibrator
import android.os.VibrationEffect
import android.os.VibratorManager
import android.media.*
import android.util.Log
import veriluscore.Veriluscore
import veriluscore.SignalResult
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.PI
import kotlin.math.sin
import kotlin.math.sqrt

class SignalIntelligence(private val context: Context) {
    fun getContext(): Context = context
    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private val magneticSensor = sensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD_UNCALIBRATED)
        ?: sensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)
    
    private val vibrator = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
        val vibratorManager = context.getSystemService(VibratorManager::class.java)
        vibratorManager?.defaultVibrator
    } else {
        context.getSystemService(Vibrator::class.java)
    }
    private val _magneticLevel = MutableStateFlow(0f)
    val magneticLevel: StateFlow<Float> = _magneticLevel
    
    private val _magneticResult = MutableStateFlow<SignalResult?>(null)
    val magneticResult: StateFlow<SignalResult?> = _magneticResult

    private val _acousticThreat = MutableStateFlow(false)
    val acousticThreat: StateFlow<Boolean> = _acousticThreat

    private var lastMagneticThreat = false

    private var audioRecord: AudioRecord? = null
    private var audioTrack: AudioTrack? = null
    private var isAnalyzing = false
    private var isJamming = false
    private var jammerJob: Job? = null
    
    private var _baselineLevel = MutableStateFlow(0f)
    val baselineLevel: StateFlow<Float> = _baselineLevel
    
    private var baselineMagnetic = 0.0
    
    // Magnetic Anomaly Detection
    private val magneticListener = object : SensorEventListener {
        override fun onSensorChanged(event: SensorEvent?) {
            event?.let {
                val x = it.values[0]
                val y = it.values[1]
                val z = it.values[2]
                val magnitude = sqrt((x*x + y*y + z*z).toDouble())
                
                if (baselineMagnetic == 0.0) {
                    baselineMagnetic = magnitude
                    _baselineLevel.value = magnitude.toFloat()
                    Log.d("SignalIntel", "Baseline set to: $baselineMagnetic uT")
                }
                
                _magneticLevel.value = magnitude.toFloat()
                
                // Use Go-based logic for consistent forensic judgment
                try {
                    val result: SignalResult? = Veriluscore.magneticScan(baselineMagnetic, magnitude)
                    val delta = magnitude - baselineMagnetic
                    
                    // FORTE: Only accept threat verdicts if they are POSITIVE spikes
                    if (result != null && delta > 10.0) {
                        _magneticResult.value = result
                        
                        if (result.hasThreat && delta > 60.0) {
                            Log.w("SignalIntel", "MAGNETIC ALERT: ${result.info}")
                        }
                        lastMagneticThreat = result.hasThreat
                    } else {
                        // Clear the result if it's a drop or neutral
                        _magneticResult.value = null
                        lastMagneticThreat = false
                    }
                } catch (e: Exception) {
                    Log.e("SignalIntel", "Native Analysis Fail: ${e.message}")
                }
            }
        }
        override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
    }

    fun startMagneticScan() {
        if (magneticSensor == null) {
            Log.e("SignalIntel", "Magnetic Sensor not found on this device.")
            return
        }
        sensorManager.registerListener(magneticListener, magneticSensor, SensorManager.SENSOR_DELAY_GAME)
    }

    fun stopMagneticScan() {
        sensorManager.unregisterListener(magneticListener)
    }

    fun resetBaseline() {
        baselineMagnetic = 0.0
        _baselineLevel.value = 0f
        _magneticResult.value = null
    }

    // Acoustic Analysis (Ear)
    @SuppressLint("MissingPermission")
    fun startAcousticAnalysis(onResult: (SignalResult) -> Unit) {
        if (isAnalyzing) return
        isAnalyzing = true
        
        val sampleRate = 44100
        val bufferSize = AudioRecord.getMinBufferSize(sampleRate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        
        audioRecord = AudioRecord(
            MediaRecorder.AudioSource.UNPROCESSED,
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            bufferSize
        )

        if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
            Log.e("SignalIntel", "Failed to initialize AudioRecord. Status: ${audioRecord?.state}")
            isAnalyzing = false
            return
        }

        CoroutineScope(Dispatchers.IO).launch {
            while (isAnalyzing) {
                val bufferSize = AudioRecord.getMinBufferSize(sampleRate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
                val record = AudioRecord(
                    MediaRecorder.AudioSource.MIC, // Shifted to MIC for better hardware compatibility during jamming
                    sampleRate,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    bufferSize.coerceAtLeast(2048)
                )

                if (record.state != AudioRecord.STATE_INITIALIZED) {
                    Log.e("SignalIntel", "Failed to initialize AudioRecord. Retrying in 2s...")
                    delay(2000)
                    continue
                }

                audioRecord = record
                val buffer = ShortArray(1024)
                
                try {
                    record.startRecording()
                    while (isAnalyzing && record.recordingState == AudioRecord.RECORDSTATE_RECORDING) {
                        val read = record.read(buffer, 0, buffer.size)
                        if (read > 0) {
                            val byteArray = ByteBuffer.allocate(read * 2)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .apply { asShortBuffer().put(buffer, 0, read) }
                                .array()

                            val result: SignalResult? = Veriluscore.acousticAnalysis(byteArray, sampleRate.toLong())
                            if (result != null) {
                                _acousticThreat.value = result.hasThreat
                                onResult(result)
                            }
                        } else if (read < 0) {
                            Log.e("SignalIntel", "AudioRecord read error: $read")
                            break // Trigger restart
                        }
                        delay(60)
                    }
                } catch (e: Exception) {
                    Log.e("SignalIntel", "Capture loop error: ${e.message}")
                } finally {
                    try {
                        record.stop()
                        record.release()
                    } catch (e: Exception) { /* Silent cleanup */ }
                }
                
                if (isAnalyzing) {
                    Log.w("SignalIntel", "Audio stream interrupted. Restarting capture...")
                    delay(1000)
                }
            }
        }
    }

    fun stopAcousticAnalysis() {
        isAnalyzing = false
    }

    // Acoustic Jammer (Jammer)
    fun startJammer(mode: JamMode) {
        if (isJamming) stopJammer()
        isJamming = true
        
        val sampleRate = 44100
        val durationSeconds = 1
        val numSamples = sampleRate * durationSeconds
        val generatedSnd = FloatArray(numSamples)
        
        // Pre-calculate the waveform buffer
        when (mode) {
            JamMode.ULTRASONIC_SWEEP -> {
                for (i in 0 until numSamples) {
                    val freq = 18000 + (4000 * (i.toDouble() / numSamples))
                    var sample = sin(2 * PI * i / (sampleRate / freq)).toFloat()
                    
                    // Kill the "Click": Apply a 10ms linear fade to the start and end
                    val fadeSamples = (sampleRate * 0.01).toInt() // 10ms
                    if (i < fadeSamples) {
                        sample *= (i.toFloat() / fadeSamples)
                    } else if (i > numSamples - fadeSamples) {
                        sample *= ((numSamples - i).toFloat() / fadeSamples)
                    }
                    
                    generatedSnd[i] = sample
                }
            }
            JamMode.WHITE_NOISE_MASK -> {
                for (i in 0 until numSamples) {
                    generatedSnd[i] = (Math.random() * 2 - 1).toFloat()
                }
            }
            JamMode.KINETIC_GLASS_MASHER -> {
                // Audio is silent in this mode, logic handled below in the coroutine
            }
        }

        jammerJob = CoroutineScope(Dispatchers.Default).launch {
            if (mode == JamMode.KINETIC_GLASS_MASHER) {
                while (isJamming) {
                    val pattern = longArrayOf(0, 150 + (Math.random() * 200).toLong(), 50 + (Math.random() * 100).toLong())
                    vibrator?.vibrate(VibrationEffect.createWaveform(pattern, -1))
                    delay(pattern.sum() + 50)
                }
                return@launch
            }
            
            try {
                val track = AudioTrack.Builder()
                    .setAudioAttributes(AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build())
                    .setAudioFormat(AudioFormat.Builder()
                        .setEncoding(AudioFormat.ENCODING_PCM_FLOAT)
                        .setSampleRate(sampleRate)
                        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .build())
                    .setBufferSizeInBytes(generatedSnd.size * 4)
                    .setTransferMode(AudioTrack.MODE_STATIC)
                    .build()

                audioTrack = track
                track.write(generatedSnd, 0, generatedSnd.size, AudioTrack.WRITE_BLOCKING)
                
                if (isJamming) {
                    track.setLoopPoints(0, numSamples, -1) // Loop infinitely
                    track.play()
                } else {
                    track.release()
                }
            } catch (e: Exception) {
                Log.e("SignalIntel", "Failed to start jammer: ${e.message}")
            }
        }
    }

    fun stopJammer() {
        isJamming = false
        jammerJob?.cancel()
        jammerJob = null
        vibrator?.cancel()
        val track = audioTrack
        audioTrack = null // Prevent further access
        
        try {
            if (track != null && track.state == AudioTrack.STATE_INITIALIZED) {
                track.stop()
                track.release()
            }
        } catch (e: Exception) {
            Log.e("SignalIntel", "Error stopping jammer: ${e.message}")
        }
    }

    enum class JamMode {
        ULTRASONIC_SWEEP,
        WHITE_NOISE_MASK,
        KINETIC_GLASS_MASHER
    }
}
