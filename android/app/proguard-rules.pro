-keep class org.rustls.platformverifier.** { *; }
-keep interface org.rustls.platformverifier.** { *; }
-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }

# Strip debug and verbose logs in release
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}
