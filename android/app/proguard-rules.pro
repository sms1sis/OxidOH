# Strip all debug and verbose logs in release
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

# Preserve JNI method names and signatures
-keepattributes Exceptions,Signature,InnerClasses,SourceFile,LineNumberTable,*Annotation*,EnclosingMethod

# Keep the ProxyService class and its members for JNI
-keep class io.github.sms1sis.oxidoh.ProxyService {
    native <methods>;
    *;
}

# Also keep the companion object explicitly just in case
-keep class io.github.sms1sis.oxidoh.ProxyService$Companion {
    public static void nativeLog(java.lang.String, java.lang.String, java.lang.String);
    *;
}

# Keep the JNI entry points
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep classes that might be used by rustls-platform-verifier

-keep class org.rustls.platformverifier.** { *; }

-keep class androidx.security.net.** { *; }
