# PIF Detector

![Platform](https://img.shields.io/badge/platform-Android-green)
![Min SDK](https://img.shields.io/badge/minSdk-24-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-red)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)

Detects [Play Integrity Fix](https://github.com/chiteroman/PlayIntegrityFix), [PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork), [TrickyStore](https://github.com/5ec1cff/TrickyStore), and the newer wave of bypass modules (inject-s v4.5 companion streaming, autopif4 Canary fingerprints, TS-Enhancer-Extreme, PIF-Hybrid Rust edition, Treat Wheel root hider) on Android, plus in-app hardware key-attestation validation that counters the 2026 STRONG-integrity keybox-spoofing stack. Native C++ detection engine with a custom bytecode VM, runtime string obfuscation, and Kotlin UI.

## Screenshots

<p align="center">
  <img src="screenshots/results_top.png" width="300" alt="Detection results - top" />
  <img src="screenshots/results_bottom.png" width="300" alt="Detection results - bottom" />
</p>

## What it detects

- **Play Integrity Fix** — maps scan for PIF classes & `InMemoryDexClassLoader` DEX regions, `custom.pif.prop`/`custom.pif.json`, module dirs, known props
- **PIF Companion Streaming (inject-s v4.5)** — Zygisk companion IPC sockets, memfd-backed dex regions, module installed without `pif.json`
- **Pixel Canary Fingerprint (autopif4)** — monthly Canary build IDs, vendor partition / `ro.build.id` mismatch, brand vs fingerprint cross-check
- **PIF Pure Rust (PIF-Hybrid)** — module.prop markers ("Pure Rust Edition", "zero DobbyHook", "Enginex0"), Rust crate libs in maps
- **TrickyStore / KeyboxHub** — `keybox.xml`, `target.txt`, `security_patch.txt` under `/data/adb/tricky_store/`, KeyboxHub auto-rotation paths, maps artifacts
- **TS-Enhancer-Extreme** — anti-detection module that masquerades the bootloader as locked; module deploy path, config dir, `tseed`/`tsees`/`tseev` Rust binaries
- **Zygisk / Magisk / KernelSU / APatch** — maps scan for zygisk libs (incl. ReZygisk, ZygiskNext, Shamiko, NoHello), env vars, `rwxp` anomalies, root-manager packages via `PackageManager` (Magisk + KernelSU + APatch + classic SuperSU/Koush/Kingo + cloakers), su binary paths (incl. `/system_ext/bin/su` on A11+), busybox, legacy SuperUser/SuperSU APKs in `/system`
- **Root Hiders** — mount namespace divergence, OverlayFS on `/system`, SELinux context anomalies, elevated rwxp anonymous mapping count
- **Treat Wheel** — closed-source "Shamiko for ReZygisk" root hider (written in C to dodge `__cxa_atexit` unload detection); `/proc/self/maps` scan for `treat_wheel/zygisk/` module mapping
- **Key Attestation Anomaly** — generates an attested EC key in `AndroidKeyStore` and runs several low-false-positive checks: (1a) cryptographically validates the certificate chain — leaf-hacking spoof modes (TrickyStore/TrickyStoreOSS/TEESimulator `?` mode) mutate the TEE leaf's attestation extension, breaking the issuer's signature; (anti-replay) verifies the attestation echoes the random challenge nonce we passed, defeating cached/replayed certs; (1b) parses the attestation `RootOfTrust` (`deviceLocked`/`verifiedBootState`) and flags a contradiction when it claims a locked/verified device while the engine's own root-hider signals prove tampering; (1c) anchors the chain to Google's hardware-attestation roots (RSA→2042 and ECDSA P-384→2035, SHA-256-pinned offline) — a self-consistent chain that does not terminate at a genuine Google root is a software/fake-keybox spoof; (1d, opt-in) for a Google-anchored chain, checks each cert serial against Google's revocation list to catch generation-mode spoofers (a leaked-but-revoked real keybox). 1d is the only check that touches the network and is **OFF by default** behind a user toggle — the app is network-silent otherwise. Fails safe throughout: absence of attestation (old/AOSP devices), parse failure, an unrecognised root, or an offline revocation fetch never flags
- **Frida / Xposed** — TCP connect probe to `127.0.0.1:27042` and `:27043`, maps scan for gadget libs, `gmain`/`gum-js-loop` thread names, parent process cmdline, Objection. The TCP probe replaces the legacy `/proc/net/tcp` scan, which Android 10+ filters to empty for `untrusted_app`.
- **Property Spoofing** — cross-validation of `ro.build.fingerprint` vs `ro.product.*`, security patch vs kernel date, board (Pixel boards must run on Tensor SoCs), property read timing
- **Bootloader** — `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.veritymode`, `vbmeta.device_state`, `ro.debuggable`, `ro.secure`, `sys.oem_unlock_allowed`
- **Debuggers** — `TracerPid` from `/proc/self/status`, `FLAG_DEBUGGABLE` (release builds only)
- **APK Tampering** — SHA-256 of the signing cert obtained via `PackageManager.GET_SIGNING_CERTIFICATES` (API 28+), pinned in native code. Skipped in debug builds.

## How PIF bypasses integrity checks

PIF runs as a Zygisk module and:

1. Hooks `__system_property_read_callback` to spoof build properties (`ro.build.fingerprint`, `ro.build.version.security_patch`, etc.)
2. Injects `classes.dex` at runtime into `com.google.android.gms.unstable` via `InMemoryDexClassLoader`
3. Uses reflection to modify `android.os.Build` fields and inject a custom `KeyStoreSpi` provider
4. TrickyStore extends this by modifying key attestation certificate chains using stolen/leaked keybox files

Newer forks add: streaming the dex payload over a Zygisk companion IPC channel (no on-disk JSON, defeats config-file scans); rotating monthly Pixel Canary fingerprints from automation; pure-Rust rewrites that ditch DobbyHook and so escape libdobby signature scans; and TS-Enhancer-Extreme, which actively patches `VerifiedBootHash` and security-patch props to make the bootloader look locked.

## Architecture

`MainActivity` is UI-only. `DetectionRunner` owns the worker executor and the JNI binding to the native engine. The native engine runs in two phases:

1. **Debug/instrumentation checks** run first (fail-fast): `isTraced()`, Frida VM + TCP-connect probe + thread scan, parent process check, debuggable flag (release only)
2. **Tampering checks** run in randomized order each time: Zygisk VM + PackageManager root-app probe + su-binary scan, PIF VM + companion-streaming probe, mount namespace, OverlayFS, SELinux, bootloader props, APK signature (SHA-256), TrickyStore paths, property consistency, Pixel Canary fingerprint, TS-Enhancer-Extreme, PIF Pure Rust, Treat Wheel

After the native call returns, `DetectionRunner` runs the **key-attestation probe** (`KeyAttestationProbe`, Kotlin — the `AndroidKeyStore` attestation API lives in Java land) and ORs `ATTEST_ANOMALY` into the bitmask. Its contradiction check reuses the root-hider bit the native engine already computed; its chain-anchor check uses the SHA-256-pinned Google roots in `AttestationRoots`. The optional online revocation check (1d) runs only when the user enables the toggle (SharedPreferences, default off), so the app stays network-silent by default. The flag bit is still registered in `nativeAllFlagsMask()` so the SSOT assertion holds; the pure validation/parse/anchor logic is isolated in `AttestationAnalysis` and unit-tested (including against real Google attestation bytes and the pinned root fingerprints). This is the only detection signal produced outside the native engine.

VM-based checks (Frida, Zygisk, PIF) use a custom bytecode interpreter with rolling-key XOR-encoded opcodes — harder to hook than direct function calls. Sensitive strings are base64+XOR encoded and only decoded at runtime.

JNI helpers use a `LocalRef<T>` RAII wrapper for ref hygiene, and security checks (signature, debuggable) fail closed: any JNI lookup error fires the detection bit so a hooked-JNI environment can't suppress it.

### SELinux awareness

`untrusted_app` on Android 10+ cannot read `/proc/net/tcp` (filtered to empty) or `access()` paths under `/data/adb/*` (denied). Detectors that target those signals use alternatives: TCP connect probes for ports, `PackageManager` for root managers, and in-process `/proc/self/maps` for module presence.

### Return value

The native function returns a bitmask — `0` means clean, any set bit indicates a detection:

```
0x0001  DEBUGGER          0x0040  TRICKYSTORE       0x0400  CANARY_FP
0x0002  FRIDA             0x0080  PROP_SPOOF        0x0800  TSEE
0x0004  ZYGISK            0x0100  ROOT_HIDER        0x1000  PIF_RUST
0x0008  PIF               0x0200  PIF_STREAM        0x2000  TREAT_WHEEL
0x0010  BOOTLOADER                                  0x4000  ATTEST_ANOMALY
0x0020  SIGNATURE
```

Flag values are owned by the native side; `DetectionRunner.verifyFlagsInSync()` asserts at startup that the Kotlin mirrors match `nativeAllFlagsMask()`.

## Build

```bash
./gradlew assembleDebug     # debug build (signature check skipped)
./gradlew assembleRelease   # release build (requires signing config)
./gradlew test              # run unit tests
./gradlew lintDebug         # run lint checks
```

Requires NDK r25+, Android Studio Hedgehog or later, SDK 35, Kotlin 2.0+. The manifest declares `INTERNET` (for Frida TCP probe) and a `<queries>` block listing root-manager package names (Android 11+ visibility requirement).

> If you build a release with your own signing key, update `EXPECTED_CERT_SHA256` in `native-lib.cpp` to the lowercase hex SHA-256 of your cert's DER bytes:
> ```
> apksigner verify --print-certs your-release.apk | grep "SHA-256"
> ```
> Debug builds skip the signature check, so you don't need to update anything for local development.

## Requirements

- Android 7.0+ (API 24)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

| Name     | GitHub |
|----------|--------|
| Ir0nByte | [@IR0NBYTE](https://github.com/IR0NBYTE) |

## License

[GPL-3.0](LICENSE) — derivative works must stay open source.

> This tool is for defensive security research. Use it only on devices you own or have permission to test.
