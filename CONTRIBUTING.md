# Contributing

## Ways to contribute

- Bug reports -open an issue with steps to reproduce
- New detection artifacts (PIF/Zygisk/Frida variants)
- Bypasses found -open a `[SECURITY]` issue or contact the maintainer directly before going public
- Code improvements, refactoring, tests

## Build

```bash
./gradlew assembleDebug
./gradlew installDebug
./gradlew assembleRelease
```

Requires Android Studio Hedgehog+, NDK r25+, SDK 35.

## Signature hash setup

Building from source means the APK integrity check will reject your binary since the signing key differs. To fix it:

1. Add this temporarily to `MainActivity.kt` inside `onCreate`:
```kotlin
try {
    val pi = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
    pi.signatures?.forEach { sig ->
        android.util.Log.w("SIG_HASH", "Hash: ${sig.hashCode()}")
    }
} catch (_: Exception) {}
```
2. `adb logcat | grep SIG_HASH` to grab the value
3. Replace `EXPECTED_SIG_HASH` in `native-lib.cpp` with your hash
4. Remove the log block and rebuild

## Code style

- Kotlin: standard Android conventions, no wildcard imports
- C++: C++17, explicit `std::`, RAII for all resources, no debug logging in native code

## Pull requests

1. Fork and branch off `main`
2. Test on a real device where possible
3. Make sure `./gradlew assembleRelease` passes before opening the PR

## License

Contributions are licensed under [GPL-3.0](LICENSE).
