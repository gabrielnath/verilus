# ============================================================
#  Verilus — Production ProGuard / R8 Rules
#  IMPORTANT: These rules are required for the gomobile AAR
#  bridge to function correctly after R8 obfuscation.
# ============================================================

# ── gomobile AAR Bridge ──────────────────────────────────
# Preserve the entire public surface of the compiled Go AAR.
# Removing or renaming these classes will break the FFI layer.
-keep class veriluscore.** { *; }
-keepclassmembers class veriluscore.** { *; }

# ── Kotlin Coroutines ────────────────────────────────────
-keepclassmembers class kotlinx.coroutines.** { volatile <fields>; }
-keepclassmembernames class kotlinx.** { volatile <fields>; }

# ── Jetpack Compose ──────────────────────────────────────
# Compose is already handled by the Compose compiler plugin,
# but keeping these prevents R8 from stripping runtime helpers.
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# ── AndroidX Core / Activity ────────────────────────────
-keep class androidx.core.** { *; }

# ── Crash Reporting: Preserve Stack Traces ──────────────
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ── Suppress warnings from Go runtime stubs ─────────────
-dontwarn go.**
-dontwarn veriluscore.**