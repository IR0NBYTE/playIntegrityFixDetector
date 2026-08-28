# PIF Detector

![Platform](https://img.shields.io/badge/platform-Android-green)
![Min SDK](https://img.shields.io/badge/minSdk-24-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-red)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)

Detects [Play Integrity Fix](https://github.com/chiteroman/PlayIntegrityFix), [PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork), [TrickyStore](https://github.com/5ec1cff/TrickyStore), and the newer wave of bypass modules (inject-s companion streaming, autopif4 Canary fingerprints, TS-Enhancer-Extreme, PIF-Hybrid Rust edition, Treat Wheel root hider) on Android, plus passive and active hardware key-attestation validation that counters the 2026 STRONG-integrity keybox-spoofing stack. Native C++ detection engine with runtime string obfuscation and a Kotlin UI.

The load-bearing signal is key attestation. Every Zygisk PIF fork gates on the target process and unloads itself everywhere else, and the keybox spoofers hook `keystore2` rather than the calling app, so from an unprivileged `untrusted_app` there is nothing of them in our own address space to find. Checks that look for module names and paths are kept for privileged runs but are labelled honestly in the UI rather than counted as coverage. See [SELinux and the privilege boundary](#selinux-and-the-privilege-boundary).

## Screenshots

<p align="center">
  <img src="screenshots/results_top.png" width="300" alt="Detection results - top" />
  <img src="screenshots/results_bottom.png" width="300" alt="Detection results - bottom" />
</p>

## What it detects

- **Play Integrity Fix:** maps scan for PIF classes & `InMemoryDexClassLoader` DEX regions, `custom.pif.prop`/`custom.pif.json`, module dirs, known props
- **PIF Companion Streaming (inject-s v4.5):** Zygisk companion IPC sockets, memfd-backed dex regions, module installed without `pif.json`
- **Pixel Canary Fingerprint (autopif4):** monthly Canary build IDs, vendor partition / `ro.build.id` mismatch, brand vs fingerprint cross-check
- **PIF Pure Rust (PIF-Hybrid):** module.prop markers ("Pure Rust Edition", "zero DobbyHook", "Enginex0"), Rust crate libs in maps
- **Keybox spoofers (TrickyStore, TrickyStoreOSS, TEESimulator, OhMyKeymint, ForgeStore, KeyboxHub):** `keybox.xml`, `target.txt`, `security_patch.txt` under `/data/adb/tricky_store/`, plus the August 2026 wave that stopped hand-building certificates and started running a real KeyMint instead: TEESimulator v4 (`/data/adb/teesim`, vendors AOSP's Rust KeyMint reference TA inside `keystore2`), OhMyKeymint (`/data/misc/keystore/omk`), ForgeStore, and KeyboxHub auto-rotation paths
- **FS-Enhancer-Extreme (was TS-Enhancer-Extreme):** anti-detection module that masquerades the bootloader as locked. Renamed in July 2026 and the config directory moved with it, so the current deployment is `fs_enhancer_extreme`; the old `ts_` paths are kept for legacy installs but no longer match a current one, and the new version in fact lists `ts_enhancer_extreme` in its own conflict-module table and disables it
- **Zygisk / Magisk / KernelSU / APatch:** maps scan for zygisk libs (incl. ReZygisk, ZygiskNext, Shamiko, NoHello, and Vector, the maintained LSPosed successor), env vars, `rwxp` anomalies, root-manager packages via `PackageManager` (Magisk + KernelSU + APatch + classic SuperSU/Koush/Kingo + cloakers), su binary paths (incl. `/system_ext/bin/su` on A11+), busybox, legacy SuperUser/SuperSU APKs in `/system`
- **Root Hiders:** mount namespace divergence, OverlayFS on `/system`, SELinux context anomalies, elevated rwxp anonymous mapping count
- **Treat Wheel:** closed-source "Shamiko for ReZygisk" root hider (written in C to dodge `__cxa_atexit` unload detection); `/proc/self/maps` scan for the `treat_wheel/zygisk/` module mapping
- **Key Attestation Anomaly:** generates an attested EC key in `AndroidKeyStore` and runs several low-false-positive checks. (1a) Cryptographically validates the certificate chain link by link, and requires every certificate that issues another to actually be a CA. Both run before a single byte of the attestation extension is parsed, because the extension is the only attacker-written input here. The `basicConstraints` half matters on its own: a genuine attested key is an end-entity certificate whose private key the attacker holds, so without it they can sign a forged leaf with a real one and hand back a chain that verifies link by link and terminates at a real Google root. A signature algorithm the platform cannot even name counts as a broken link rather than as an unchecked one, since that OID is theirs to write. (anti-replay) Verifies the attestation echoes the random challenge nonce we passed, defeating cached and replayed certs. (1b) Parses the attestation `RootOfTrust` (`deviceLocked`/`verifiedBootState`) and flags a contradiction when it claims a locked/verified device while the engine's own root-hider signals prove tampering. (1c) Anchors the chain to Google's hardware-attestation roots (RSA valid through 2042 and ECDSA P-384 valid through 2035, SHA-256-pinned offline). Chains that report `attestationSecurityLevel = Software` are exempt from anchoring: those are signed by the public AOSP software attestation key, which is deliberately not pinned, so emulators, GSI images and AOSP builds fail anchoring while being completely clean. (1d, opt-in) For a Google-anchored chain, checks each cert serial against Google's revocation list. That list is not uniformly hex: of its 1742 entries, 974 are decimal-keyed, so each serial is looked up in both encodings. This is the only check that touches the network and is **OFF by default** behind a user toggle, so the app stays network-silent otherwise. Fails safe throughout: absence of attestation, parse failure, an unrecognised root, or an offline revocation fetch never flags.
- **Attestation Forgery (active):** rather than inspecting whatever chain a spoofer chooses to hand back, this asks for keys that are awkward to forge and catches the answer contradicting itself. It requests a `PURPOSE_ATTEST_KEY` key, which TrickyStoreOSS forges for **any** caller because that arm of its force-forge condition carries no uid gate, so the forgery is provoked even when the detector is not in the module's `target.txt`. It also requests an auth-bound key with a SHA-512 digest, which surfaces two more contradictions: a leaf signed with the digest we asked for rather than the batch key's fixed SHA-256, and an authorization list asserting `NO_AUTH_REQUIRED` (tag 503) for a key that plainly requires authentication while omitting tags 504/505. The tag-503 half now fires on nothing current and is retained only for the TEESimulator v3 line and older installs: TrickyStoreOSS made that tag conditional on 2026-07-31, sixteen hours after the v2.5 release, and the KeyMint reimplementations emit it honestly. It is recorded here rather than quietly left in place, because a check whose description claims coverage it no longer has is exactly the failure this project keeps auditing for. A single self-signed certificate carrying an attestation extension is caught too. When the passive probe has already flagged, the anchoring half is suppressed so a device with no hardware attestation is reported once rather than twice.
- **Frida / Xposed:** TCP connect probe to `127.0.0.1:27042` and `:27043`, maps scan for gadget libs, `gmain`/`gum-js-loop` thread names, parent process cmdline, Objection. The TCP probe replaces the legacy `/proc/net/tcp` scan, which Android 10+ filters to empty for `untrusted_app`.
- **Property Spoofing:** cross-validation of `ro.build.fingerprint` vs `ro.product.*`, board (Pixel boards must run on Tensor SoCs), property read timing, and build-identity self-contradiction. PIFork, inject-s and FS-Enhancer-Extreme all globally reset `ro.build.type` to `user` and every `ro.*.build.tags` to `release-keys`, but none of them rewrites a fingerprint property globally, because fingerprint spoofing lives in their Zygisk layer and that only loads inside GMS and the Play Store. A genuine fingerprint always ends in `:<build_type>/<tags>`, so the scalars disagreeing with it proves something rewrote them after the image was built. The check is directional and only fires when the scalars claim a clean production build, which makes it inert on both genuine user builds and genuine userdebug builds. It therefore only catches this on a device whose ROM is really userdebug or eng.
- **Bootloader:** `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.veritymode`, `vbmeta.device_state`, `ro.debuggable`, `ro.secure`, `sys.oem_unlock_allowed`
- **Debuggers:** `TracerPid` from `/proc/self/status`, `FLAG_DEBUGGABLE` (release builds only)
- **APK Tampering:** SHA-256 of the signing cert obtained via `PackageManager.GET_SIGNING_CERTIFICATES` (API 28+), compared against a digest injected at build time. Skipped in debug builds, and in release builds when no digest is supplied. See [Build](#build).

## How PIF bypasses integrity checks

PIF runs as a Zygisk module and:

1. Hooks `__system_property_read_callback` to spoof build properties (`ro.build.fingerprint`, `ro.build.version.security_patch`, etc.)
2. Injects `classes.dex` at runtime into `com.google.android.gms.unstable` via `InMemoryDexClassLoader`
3. Uses reflection to modify `android.os.Build` fields and inject a custom `KeyStoreSpi` provider
4. TrickyStore extends this by modifying key attestation certificate chains using stolen/leaked keybox files

Newer forks add: streaming the dex payload over a Zygisk companion IPC channel (no on-disk JSON, defeats config-file scans); rotating monthly Pixel Canary fingerprints from automation; pure-Rust rewrites that ditch DobbyHook and so escape libdobby signature scans; and TS-Enhancer-Extreme, which actively patches `VerifiedBootHash` and security-patch props to make the bootloader look locked.

## Architecture

`MainActivity` is UI-only. `DetectionRunner` owns the worker executor and the JNI binding to the native engine. The native engine runs in two phases:

1. **Debug/instrumentation checks** run first (fail-fast): `isTraced()`, Frida TCP-connect probe and thread scan, parent process check, debuggable flag (release only)
2. **Tampering checks** run in randomized order each time: Zygisk maps scan plus PackageManager root-app probe and su-binary scan, PIF side-effect probe, companion-streaming probe, mount namespace, OverlayFS, SELinux, bootloader props, APK signature, TrickyStore paths, property consistency, Pixel Canary fingerprint, TS-Enhancer-Extreme, PIF Pure Rust, Treat Wheel

The native engine needs a `Context` for the three checks that touch the framework (root-manager package probe, debuggable flag, APK signature), so `isIntegrityTampered` takes one explicitly. It previously received the `DetectionRunner` instance instead, which under CheckJNI aborts the process and without it is undefined behaviour that made all three silently fail open.

After the native call returns, `DetectionRunner` runs the **passive key-attestation probe** (`KeyAttestationProbe`, written in Kotlin because the `AndroidKeyStore` attestation API lives in Java land) and ORs `ATTEST_ANOMALY` into the bitmask, then the **active probe** (`ActiveAttestationProbe`) which ORs `ATTEST_FORGERY`. The active probe is told whether the passive one already flagged, so a device with no hardware attestation at all is not reported twice for one cause. Its contradiction check reuses the root-hider bit the native engine already computed; its chain-anchor check uses the SHA-256-pinned Google roots in `AttestationRoots`. The optional online revocation check (1d) runs only when the user enables the toggle (SharedPreferences, default off), so the app stays network-silent by default. The flag bit is still registered in `nativeAllFlagsMask()` so the SSOT assertion holds; the pure validation/parse/anchor logic is isolated in `AttestationAnalysis` and unit-tested (including against real Google attestation bytes and the pinned root fingerprints). This is the only detection signal produced outside the native engine.

Sensitive strings are base64+XOR encoded and only decoded at runtime. An earlier obfuscation VM was removed in v2.4: its rolling-key decoder desynced on every taken jump, so all three VM-backed checks always returned false. Its unique needles were folded into the direct scanners before the VM was deleted.

JNI helpers use a `LocalRef<T>` RAII wrapper for ref hygiene, and security checks (signature, debuggable) fail closed: any JNI lookup error fires the detection bit so a hooked-JNI environment can't suppress it.

### SELinux and the privilege boundary

`untrusted_app` on Android 10+ cannot read `/proc/net/tcp` (filtered to empty) or `access()` paths under `/data/adb/*` (denied). Detectors that target those signals use alternatives: TCP connect probes for ports, `PackageManager` for root managers, and in-process `/proc/self/maps` for module presence.

The boundary is wider than the filesystem, and it decides what this app can honestly claim:

- **The PIF forks are not in our process.** Both PIFork and inject-s gate on `app_data_dir` ending in `/com.google.android.gms` or `/com.android.vending` and call `DLCLOSE_MODULE_LIBRARY` in every other process. FS-Enhancer-Extreme has no Zygisk component at all. A maps scan for them cannot match.
- **The keybox spoofers are not in our process either.** TrickyStoreOSS and ForgeStore ptrace-inject into `keystore2` and hook `ioctl` there. Their effect reaches us only through the attestation chain.
- **The kernel's own copy of boot state is unreadable.** `ro.boot.*` derives from `androidboot.*`, and no module touches `/proc/cmdline` or `/proc/bootconfig`, so the contradiction is real but out of reach: AOSP sepolicy grants `proc_cmdline` and `proc_bootconfig` to no app domain. `/sys/fs/selinux/enforce` carries an explicit `neverallow` for untrusted apps, `/proc/version` is denied, and `/system/build.prop` is mode 0600. `/proc/cpuinfo` is the one kernel-exposed source apps may still read, which is why the SoC cross-check works.

Five flags therefore cannot fire unprivileged: `PIF`, `TRICKYSTORE`, `PIF_STREAM`, `TSEE` and `PIF_RUST`. They are retained because they do fire when the app runs with root or adb, but the UI renders them as **NOT OBSERVABLE** in grey rather than a green pass, and excludes them from the summary count, so the result list never implies coverage the sandbox forbids. `TREAT_WHEEL` is deliberately not in that set: it is a ReZygisk root hider that loads into every app process including ours, so its in-process scan genuinely fires.

### Return value

The native function returns a bitmask: `0` means clean, any set bit indicates a detection.

```
0x0001  DEBUGGER          0x0040  TRICKYSTORE       0x0400  CANARY_FP
0x0002  FRIDA             0x0080  PROP_SPOOF        0x0800  TSEE
0x0004  ZYGISK            0x0100  ROOT_HIDER        0x1000  PIF_RUST
0x0008  PIF               0x0200  PIF_STREAM        0x2000  TREAT_WHEEL
0x0010  BOOTLOADER                                  0x4000  ATTEST_ANOMALY
0x0020  SIGNATURE                                   0x8000  ATTEST_FORGERY
```

Flag values are owned by the native side; `DetectionRunner.verifyFlagsInSync()` asserts at startup that the Kotlin mirrors match `nativeAllFlagsMask()`.

## Build

```bash
./gradlew assembleDebug     # debug build (signature check skipped)
./gradlew assembleRelease   # release build (requires signing config)
./gradlew test              # run unit tests
./gradlew lintDebug         # run lint checks
```

Requires NDK r25+, Android Studio Hedgehog or later, SDK 35, Kotlin 2.0+. The manifest declares `INTERNET` (used by the Frida TCP probe and the opt-in attestation revocation check) and a `<queries>` block listing root-manager package names (Android 11+ visibility requirement).

The APK signature check pins the release signing certificate. Supply its digest through the environment at build time:

```bash
export RELEASE_CERT_SHA256=$(keytool -list -v -keystore <ks> -alias <alias> \
  | grep SHA256: | sed 's/.*SHA256: //' | tr -d ':' | tr 'A-Z' 'a-z')
./gradlew assembleRelease
```

Leave it unset and the check compiles out, exactly as it does for debug builds. It used to be a constant in `native-lib.cpp`, which silently pinned every release to whichever machine last edited the file; because the check is fail-closed, a build signed with any other key then reported its own signature as tampered on every device. Absent is safer than wrong.

## Requirements

- Android 7.0+ (API 24)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

| Name     | GitHub |
|----------|--------|
| Ir0nByte | [@IR0NBYTE](https://github.com/IR0NBYTE) |

## License

[GPL-3.0](LICENSE). Derivative works must stay open source.

> This tool is for defensive security research. Use it only on devices you own or have permission to test.

