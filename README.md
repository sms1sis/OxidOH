# OxidOH

A Rust implementation of an Oblivious DNS over HTTPS (ODoH) proxy designed to be compatible with the Android frontend of `https_dns_proxy_rust`.

## Project Goals

*   Provide a Rust-based ODoH proxy backend.
*   Maintain compatibility with the existing JNI interface and Android frontend structure of `https_dns_proxy_rust`.
*   Offer enhanced privacy features through ODoH.

## Building for Android

This project uses `cargo-ndk` to build the Rust library for Android.

### Prerequisites

1.  **Rust and Cargo:** Ensure you have Rust and Cargo installed. You can install them via `rustup`:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2.  **`rustup` targets for Android:** Add the necessary Rust targets for Android:
    ```bash
    rustup target add aarch64-linux-android
    ```
3.  **Android NDK:** Download and install the Android NDK. You can typically do this through Android Studio's SDK Manager, or manually.
    *   **Set `ANDROID_NDK_HOME`:** You *must* set the `ANDROID_NDK_HOME` environment variable to point to your NDK installation directory. For example:
        ```bash
        export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/YOUR_NDK_VERSION
        ```
        (Replace `YOUR_NDK_VERSION` with the actual version, e.g., `29.0.14206865`)
4.  **`cargo-ndk`:** Install the `cargo-ndk` tool:
    ```bash
    cargo install cargo-ndk
    ```

### Build Steps

1.  Navigate to the `OxidOH` project directory:
    ```bash
    cd OxidOH
    ```
2.  Make the `build_android.sh` script executable:
    ```bash
    chmod +x build_android.sh
    ```
3.  Run the build script:
    ```bash
    ./build_android.sh
    ```

This script will compile the Rust code for `aarch64-linux-android` (arm64-v8a) and place the resulting `liboxidoh.so` file into the `android/app/src/main/jniLibs/arm64-v8a/` directory, assuming a standard Android project structure relative to `OxidOH`.

### Integration with Android App

The `liboxidoh.so` library exposes the same JNI functions as `https_dns_proxy_rust`. To integrate:

1.  Ensure your Android project's `ProxyService.kt` (or equivalent) in the `io.github.oxidoh` package loads the `oxidoh` library:
    ```java
    static {
        System.loadLibrary("oxidoh");
    }
    ```
2.  Update the native method declarations in your Java/Kotlin code to call the `oxidoh` library's functions. The method signatures are designed to be identical to those in `https_dns_proxy_rust`.

## Usage (Android)

Once integrated, the Android application can start and stop the ODoH proxy, get latency statistics, and query logs using the existing frontend UI elements that interact with the native methods.

The `resolver_url` provided to the `startProxy` function should be the URL of an ODoH target server. The library will attempt to fetch the ODoH configuration from `resolver_url/.well-known/odohconfigs`.

## Contributing

Contributions are welcome! Please open an issue or pull request.
