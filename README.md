# OxidOH

A Rust implementation of an Oblivious DNS over HTTPS (ODoH) proxy for Android, featuring unique hexagonal branding and robust connectivity.

## Features

- **Rust-Powered Proxy:** High-performance ODoH backend for enhanced privacy.
- **Robust Config Fetching:** Implements RFC 9230 with multi-path fallbacks, automatic retries (5 attempts), and rotated User-Agents (oxidoh/0.1.1).
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

## ODoH Profiles & Privacy

The application offers several connection profiles. Selecting a **Relayed** profile is required for "True ODoH" privacy (hiding your IP from the resolver).

| Profile | Type | Privacy Level | Use Case |
| :--- | :--- | :--- | :--- |
| **Cloudflare Direct** | Direct | High (Encryption) | Maximum speed using Cloudflare's global network. Resolver sees your IP. |
| **Cloudflare via Tiarap** | **Relayed** | **Maximum (Oblivious)** | Hides your IP from Cloudflare using Tiarap's Japan-based relay. |
| **Cloudflare via Fastly** | **Relayed** | **Maximum (Oblivious)** | Hides your IP from Cloudflare using Fastly's global edge network. |
| **Tiarap Direct** | Direct | High (Encryption) | Direct connection to Tiarap's privacy-focused resolver. |
| **Snowstorm Direct** | Direct | High (Encryption) | Community-driven independent DNS for decentralization. |

### The 6 Requirements for "Real" ODoH
This app is designed to fulfill all requirements for true Oblivious DNS-over-HTTPS in Relayed mode:
1. **No direct contact** between your device and the DNS resolver.
2. **Proxy-First routing** where queries are sent to a relay.
3. **Zero-Knowledge Proxy:** The relay cannot see which websites you are visiting.
4. **Resolver Anonymity:** The DNS resolver cannot see your original IP address.
5. **Double Encryption:** DNS payloads are encrypted for the resolver and wrapped in TLS for the proxy.
6. **Explicit ODoH Support:** Full implementation of RFC 9230 (not just standard DoH).

## Technical Details

- **Backend:** Built with `tokio`, `reqwest`, and `odoh-rs`.
- **Networking:** Uses `SO_REUSEADDR/PORT` for stable restarts and custom JNI logging for real-time diagnostics.
- **Frontend:** Modern Jetpack Compose UI with real-time latency and query logging.

## Contributing

Contributions are welcome! Please open an issue or pull request.
