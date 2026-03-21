# ── Logging ───────────────────────────────────────────────────────────────────
# Strip verbose/debug logs in release builds only (keep warn/error for crash reports)
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# ── Debug metadata ────────────────────────────────────────────────────────────
# Preserve source file names and line numbers for readable stack traces
-keepattributes Exceptions,Signature,InnerClasses,SourceFile,LineNumberTable,*Annotation*,EnclosingMethod

# ── JNI stability ─────────────────────────────────────────────────────────────
# Preserve all members of ProxyService - R8 must not rename or remove anything
# that the Rust JNI bridge calls by name.
-keep class io.github.sms1sis.oxidoh.ProxyService {
    *;
}
-keep class io.github.sms1sis.oxidoh.ProxyService$Companion {
    public static void nativeLog(java.lang.String, java.lang.String, java.lang.String);
    *;
}

# Preserve all native method entry points across the entire app
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# Keep all classes in our package to prevent aggressive R8 merging from
# breaking JNI method name resolution (e.g. ProxyTileService, BootReceiver)
-keep class io.github.sms1sis.oxidoh.** { *; }

# ── TLS / Network ─────────────────────────────────────────────────────────────
# rustls-platform-verifier JNI bridge
-keep class org.rustls.platformverifier.** { *; }
-keep class androidx.security.net.** { *; }

# ── Coroutines ────────────────────────────────────────────────────────────────
# Prevent R8 from removing coroutine state machine classes
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.coroutines.** {
    volatile <fields>;
}

# ── Compose ───────────────────────────────────────────────────────────────────
-keep class androidx.compose.** { *; }
-keepclassmembers class * {
    @androidx.compose.runtime.Composable *;
}
