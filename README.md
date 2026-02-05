# OxidOH

A Rust implementation of an Oblivious DNS over HTTPS (ODoH) proxy for Android, featuring unique hexagonal branding and robust connectivity.

## Features

- **Rust-Powered Proxy:** High-performance ODoH backend for enhanced privacy.
- **Robust Config Fetching:** Implements RFC 9230 with multi-path fallbacks, automatic retries (5 attempts), and rotated User-Agents.
- **Verified Service Providers:** Curated list of high-reliability ODoH targets and relays (Cloudflare, Tiarap, Snowstorm).
- **Dynamic Service Switching:** Optimized background service for seamless switching between providers.
- **Hexagonal Branding:** Custom hexagonal launcher and notification icons for a modern look.
- **Smart Bootstrapping:** Hardcoded fallbacks for unreliable providers to ensure constant connectivity.
- **Activity Logging:** Real-time feedback in the app's activity tab, including detailed error reporting.

## Building for Android

### Prerequisites

1.  **Rust & Cargo:** Install via `rustup`.
2.  **Android Targets:** Add `aarch64-linux-android` target.
3.  **Android NDK:** Set `ANDROID_NDK_HOME` environment variable.
4.  **cargo-ndk:** `cargo install cargo-ndk`.

### Build Steps

1.  **Build Native Library:**
    ```bash
    ./build_android.sh
    ```
2.  **Assemble APK:**
    ```bash
    cd android && ./gradlew assembleDebug
    ```

## Usage

Select from verified high-reliability profiles:
- **Cloudflare Direct:** Optimized for speed and privacy.
- **Cloudflare via Tiarap:** Regional proxying for enhanced obfuscation.
- **Cloudflare via Fastly:** Global relaying via Fastly's edge compute.
- **Tiarap / Snowstorm:** Independent high-privacy targets.

The app automatically handles ODoH configuration fetching and maintains a heartbeat to ensure the proxy is always active.

## Technical Details

- **Backend:** Built with `tokio`, `reqwest`, and `odoh-rs`.
- **Networking:** Uses `SO_REUSEADDR/PORT` for stable restarts and custom JNI logging for real-time diagnostics.
- **Frontend:** Modern Jetpack Compose UI with real-time latency and query logging.

## Contributing

Contributions are welcome! Please open an issue or pull request.
