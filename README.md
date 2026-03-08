# Play Integrity Fix Detector

![Platform](https://img.shields.io/badge/platform-Android-green)
![Min SDK](https://img.shields.io/badge/minSdk-24-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-red)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)

An Android security tool that detects whether [Play Integrity Fix](https://github.com/chiteroman/PlayIntegrityFix) or related tampering modules are active on a device. Built in native C++ and Java with a custom bytecode VM, runtime string obfuscation, and multi-layer behavioral detection.

## What it detects

- **Play Integrity Fix** — scans `/proc/self/maps` for injected PIF classes, checks known system properties and config file paths
- **Zygisk / Magisk** — maps scan for zygisk libs, `rwxp` permission anomalies on `libandroid_runtime.so`, env vars, system properties
- **Frida / Xposed** — `/proc/net/unix` socket scan, parent process cmdline check
- **Debuggers** — `TracerPid` from `/proc/self/status`
- **Unlocked bootloader** — `ro.boot.verifiedbootstate`, `ro.boot.veritymode`, `ro.boot.flash.locked`
- **APK tampering** — signing certificate hash pinned in native code, debuggable flag check

## How PIF bypasses integrity checks

PIF runs as a Zygisk module and:

1. Hooks `__system_property_read_callback` to spoof build properties (`ro.build.version.sdk`, `ro.build.version.security_patch`, `ro.build.id`)
2. Injects `classes.dex` at runtime into `com.google.android.gms.unstable`
3. Uses reflection to modify `android.os.Build` fields and inject a custom `KeyStoreSpi` provider into AndroidKeyStore

## Architecture

Detection logic runs inside a custom VM with 30+ opcodes rather than direct function calls, making it harder to hook individual checks. Sensitive strings are XOR + Base64 encoded and decoded at runtime only. The JNI entry point uses a random function name with class/method names decoded in `JNI_OnLoad`.

```
app/src/main/
├── java/.../MainActivity.java   — UI, background thread runner
└── cpp/
    ├── CMakeLists.txt
    └── native-lib.cpp           — VM, detection engine, JNI bridge
```

Return values from the native layer:

| Value | Meaning |
|-------|---------|
| `-1` | Debugger or Frida detected |
| `0`  | Clean |
| `1`  | PIF, Zygisk, or compromised bootloader |

## Build

```bash
./gradlew installDebug    # debug build + install
./gradlew assembleRelease # release build
```

Requires NDK r25+, Android Studio Hedgehog or later, SDK 35.

> If you build from source with your own signing key, update `EXPECTED_SIG_HASH` in `native-lib.cpp`. See [CONTRIBUTING.md](CONTRIBUTING.md) for how.

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
