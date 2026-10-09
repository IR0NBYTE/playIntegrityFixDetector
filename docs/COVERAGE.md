# Detection coverage

What each flag actually observes, whether it can fire from an unprivileged
untrusted_app, and what defeats it. This file exists because a check that
"exists" is not a check that "fires", and a README that implies otherwise is the
failure this project keeps auditing for.

Measured on a Pixel 7a (lynx), Android 15, Magisk 28.1 with Shamiko v1.2.1 and
Vector v2.2, no keystore spoofing module, unless a row says otherwise.

The attestation-record rows added in 2.9 were additionally measured on two
stock, locked, green-boot handsets from other vendors, because several of them
could not be justified from one device family:

| Device | Android | SDK | first_api_level | keystore feature | Attested versions | system / vendor patch |
|---|---|---|---|---|---|---|
| Pixel 7a (lynx) | 15 | 35 | 33 | 300, StrongBox 300 | schema 300, KeyMint 300 | 2024-12-05 / 2024-12-05 |
| Samsung SM-G780G (r8q) | 13 | 33 | 29 | 4, StrongBox 4 | schema 3, Keymaster 4.0 | 2024-09-01 / 2024-09-01 |
| Motorola moto g04 (lion) | 14 | 34 | 34 | 200 | schema 200, KeyMint 200 | 2025-08-05 / 2025-04-05 |

Every attestation-record row below is silent on all three. The root and hook
rows are not in scope for that claim: the Pixel in this population is the
rooted, bootloader-unlocked test unit, and the rows that say so fire on it.

Three measurements from that population are load-bearing and are cited in the
rows that rest on them:

- The attested verifiedBootHash equals `ro.boot.vbmeta.digest` on all three,
  across three vendors, which is what the boot-hash arm was waiting for. The
  arm fires only when both sides are real 32-byte digests that differ; an
  all-zero or odd-length attested hash is reported, not called.
- `ro.vendor.build.security_patch` reads empty to the app on the Pixel and the
  moto g04 and non-empty on the Samsung, so its readability is a per-vendor
  sepolicy decision and no finding may depend on it.
- The Samsung's clock is a year behind and the moto g04's is thirteen months
  behind. Both are genuine retail devices. Any check that compares a
  certificate against the device clock would have flagged them.

## Flags

| Flag | Sub-checks | Fires unprivileged | Evidence | Known counter |
|---|---|---|---|---|
| DEBUGGER | TracerPid, FLAG_DEBUGGABLE (release only) | Yes | Both work in-process | Any debugger that clears TracerPid |
| FRIDA | TCP connect to 27042/27043, thread names, maps scan, parent cmdline, legacy /proc/net/tcp | Partly | Port, thread and maps checks work in-process. Two arms fail open: the parent-cmdline read needs /proc/<ppid>/cmdline, which hidepid denies, and the /proc/net/tcp scan is filtered empty for untrusted_app on Android 10+ | A gadget on a non-default port with renamed threads |
| ZYGISK | maps needles, env vars, ro.magisk.zygisk, /data/adb probes, root-manager packages, su and busybox paths, module names from mountinfo | Yes | Fires on the test device via maps and the new mountinfo module-name harvest | Trace-cleaning Zygisk implementations, denylist, a renamed manager package |
| ROOT_HIDER | mountinfo source and mount-root analysis, OverlayFS on /system, anonymous rwxp count | Yes | Fires on the test device: 6 tmpfs mounts over system partitions whose source is not tmpfs, plus one /adb/ bind that leaks the module name | The app being on the denylist, and SUSFS sus_mount, which falsifies mountinfo in kernel |
| BOOTLOADER | verifiedbootstate, flash.locked, veritymode, vbmeta.device_state, ro.debuggable, ro.secure, oem_unlock_allowed | Partly | Reads what the properties say. ro.secure is labelled userdebug_or_eng_prop and is denied to untrusted_app, so that arm silently no-ops | Any resetprop-based property sanitizer; all of these are ordinary properties |
| SIGNATURE | signing cert SHA-256 against a build-time digest, fail-closed | Yes | Works; compiled out in debug and when no digest is supplied | Signature-spoofing frameworks that swap the PackageInfo CREATOR |
| PROP_SPOOF | fingerprint vs brand, production-claim vs build type and tags, property read latency, board vs SoC | Yes | Directional, only fires when the scalars claim a clean production build | Global, self-consistent property rewriting |
| CANARY_FP | global Pixel Canary build id, vendor fingerprint mismatch, brand cross-check | Yes | Only catches global fingerprint spoofing | Zygisk-scoped spoofing, which never reaches our process |
| CODE_INTEGRITY | libc prologue inline-hook decode (arm64-v8a and x86_64 only), executable mappings from unrecognised sources, PLT GOT slots pointing outside any recognised code source, libc text against the file on disk | Yes | Reads only this process's own address space, so no privilege is involved. Measured silent on a clean API 34 emulator and on a rooted Samsung A06: Magisk's root is filesystem-level and inline-hooks nothing in our process, so silence there is the correct answer rather than a dead check. The arms are proven to fire by the native self test, which synthesises arm64 and x86_64 trampolines and maps an anonymous executable page on every device the suite runs on | A hider that hooks nothing in our address space is invisible to it, by construction. On armeabi-v7a and x86 the prologue arm does not run at all: only arm64-v8a and x86_64 have decoders, and the other two report nothing rather than guess at byte patterns nobody verified. The text comparison is corroboration only and never fires alone, because a hider that can patch a prologue can also redirect a read of the library file |
| TREAT_WHEEL | maps needle | Yes | In-process, genuinely fires | A renamed build |
| ATTEST_ANOMALY | chain signatures, CA issuers, root anchoring, challenge echo, RootOfTrust vs tamper, boot properties vs RootOfTrust | Yes | Fires on the test device: properties claim locked while the genuine Titan M2 reports the bootloader unlocked | A keystore simulator that also sanitizes the properties it contradicts |
| ATTEST_FORGERY | attest-key provocation, auth-bound SHA-512 provocation, self-signed single cert, plus two keystore boundary probes: a key generated with no attestation challenge, and a challenge one byte past the documented 128 byte maximum | Yes | Works. The tag-503 arm now fires on nothing current and is retained only for TEESimulator v3 and older. The boundary arms are silent on both bench devices, which is the documented answer: a no-challenge key comes back self-signed with no record, and a 129 byte challenge draws INVALID_INPUT_LENGTH. Both are quoted from the KeyMint HAL, and both are answered by KeyMint rather than by the framework, so they reach the layer a simulator replaces | Simulators that honour setAttestKeyAlias and auth-bound keys. For the boundary arms, a simulator that reproduces both behaviours exactly. The known false positive vector is an OEM KeyMint that accepts an over-limit challenge: Tag.aidl says INVALID_INPUT_LENGTH "should" be returned rather than must, so a non-conformant implementation would be reported |
| ATTEST_REVOKED | chain serials against Google's published revocation list, offline snapshot plus optional online refresh. Informational only: sets no detection bit | Yes | See the section below | A keybox not yet published as revoked, which is the normal case for a fresh rotation |
| ATTEST_CROSS_SOURCE | attested osPatchLevel NEWER than `ro.build.version.security_patch`, which is ungated because CTS forbids it in every configuration; the two levels DISAGREEING in either direction, behind a locked-and-verified gate plus a Keymaster 4 gate; the attested verifiedBootHash differing from `ro.boot.vbmeta.digest` when both are real 32-byte digests; and a day-precision tag that is neither a valid date nor a month. Five arms are computed and reported but do NOT drive the verdict: both vendor-patch arms, the absent boot patch level, a month-precision day field, and an attested boot hash carrying no usable digest | Yes | Silent on all three. The OS comparison resolves real-to-real on each (202412, 202409, 202508). The boot-hash arm drives the verdict on the strength of three vendors agreeing plus the VTS assertion, rather than one device family | A simulator that also rewrites the properties in the same pass, or scopes its spoof to other packages so our process is served the genuine record |
| ATTEST_SOFTWARE | software-level attestation on a device presenting as production hardware with a declared hardware-backed keystore | Yes | Silent on the test device, whose chain is TrustedEnvironment and Google anchored | Presenting honestly as an emulator, which is also the legitimate case |
| ATTEST_VALIDITY | Issuer certificate validity windows. An inverted or zero-width window is the only finding. Expiry, a clock behind the derived floor, and a recent lapse are reported and set no bit | Yes | Silent on all three. The moto g04 reports CLOCK_BEHIND, which is correct: its clock is thirteen months behind, and that is exactly the state in which a genuine device serves a lapsed certificate. That outcome renders as not observable rather than as a review item, because a wrong device clock is a condition of the device and two of the three test handsets have one. Expiry is judged against a floor built only from witnesses that cannot be later than now (issuer notBefore, the newest embedded root, attested and system patch months), never from the device clock | Nothing: expiry is not a finding here by design. Google's own attestation guidance tells verifiers to trust chains to the published roots regardless of validity period, and batch certificates are shared across a production run |
| ATTEST_VERSION | Attested schema and KeyMint versions against the most this platform can emit, from each release's frozen KeyMint AIDL, and against the device's own hardware_keystore feature declaration. Row identity only; nothing sets this bit | Yes | Silent on all three: each sits at or below its bound (300/300 at SDK 35, schema 3 and Keymaster 4.0 at SDK 33, 200/200 at SDK 34). The Samsung declares feature version 4, which is not a centennial KeyMint version, so the declared-HAL arm correctly skips it | Nothing to defeat. The named adversary moved this field in the LOW direction, which a high-side comparison cannot catch, and a vendor TA update past the system image's own release makes a genuine device read as ahead of its bound |
| ATTEST_SHAPE | A known schema tag repeated WITHIN one authorization list, a tag the schema never attests, and a tag in the list it cannot belong to. Tag ORDER is reported in the row detail only, with no bit and no badge | Yes | Silent on all three, which emit identical ascending hardware-enforced lists `[1,2,3,5,10,503,702,704,705,706,718,719]` and software lists `[701,709]` | Emit a well-formed list, which every current stack does. Order is not usable: a genuine retail Motorola Edge (2022) emits a descending list and passes Google's own verifier |
| ATTEST_MODULE_HASH | Attested moduleHash (tag 724) against the hash the platform reports for its own module set. Row identity only; nothing sets this bit | Needs Android 16 and a KeyMint 4.0 vendor HAL; unverified, because no device in this population has either | Not applicable on all three: none reports KeyMint 4.0 (version 400), so none carries tag 724, and the platform read returns nothing below SDK 36. The comparison has therefore never executed on any device available to this project | A mismatch cannot convict in either direction: the TA pins the hash for its session, so a userspace reboot applying a staged mainline update leaves the platform ahead of the record on a genuine device |
| PIF, TRICKYSTORE, PIF_STREAM, TSEE, PIF_RUST | module directories and config files under /data/adb, companion sockets | **No** | /data/adb is SELinux-denied to untrusted_app. Retained for privileged runs, rendered NOT OBSERVABLE in the UI and excluded from the observable count | Not applicable; these cannot fire on a normal install |

## Keybox revocation, and what a pass means

The check compares every certificate serial in the attestation chain against
Google's published revocation list, using a bundled offline snapshot and, when
enabled, a live refresh.

**No revocation outcome sets a detection bit.** The published list revokes
attestation batch keys, and a batch key is shared by every handset in the
production run it was provisioned into, so a leaked keybox carries the same
serial on a spoofer's chain and on a stock, never-rooted phone from that batch.
26 of the current entries are additionally reason SOFTWARE_FLAW, which says the
device implementation is defective rather than that anyone is spoofing. Marking
those devices would be a permanent false positive their owner could not clear,
so the outcome is reported on its own row and left for the user to weigh.

Five outcomes, four of which the UI can show:

- **VERIFIED**: the serials are not on the list. This means *not known-bad*. It
  is not proof the keybox is genuine.
- **REPORTED** (KNOWN_REVOKED): a serial is on the list. Rendered amber, counted as
  neither a pass nor a detection, with the batch-key caveat stated on the row.
- **UNVERIFIED** (UNVERIFIABLE): neither the snapshot nor the network could be
  consulted. Neither a pass nor a detection.
- **UNVERIFIED** (NOT_APPLICABLE): there was no Google-anchored chain, so there
  was nothing to look up. Renders as NOT OBSERVABLE, with its own row text.
- **UNVERIFIED** (NOT_EVALUATED): an earlier trust gate failed, so the chain was
  never examined. Distinct from NOT_APPLICABLE, which asserts something about
  anchoring that those gates have not established.

What it cannot catch: Google publishes a revocation some time after a keybox is
known to be compromised. The orchestration modules on the bypass side keep their
own internal lists and mark a keybox bad well before its serial appears in the
public feed, so a freshly rotated keybox is routinely absent from it. Revocation
is a floor, not a verdict.

Pinned trust anchors are skipped before the lookup. A revoked root would be a
fleet-wide CA event rather than evidence about one device, and including it
would flag every honest user at once. The skip is decided by public key, not by
encoded bytes: Google issues one attestation key as four certificates with
different windows, and a handset keeps serving whichever instance it was
provisioned with, so a byte comparison skipped only the instance this build
happens to embed. All five published roots are now pinned, which makes the byte
comparison complete as of this build; the key comparison is what keeps it
correct when Google issues a sixth.

Snapshot cadence: regenerated by `tools/revocation/refresh_snapshot.py`, which
refuses to write on a short, malformed, or anomalously shrinking list.

## Boundary probes that were specced and not built

Four more request shapes were specced for the boundary probe. None shipped, and
the reasons are worth keeping so they are not re-proposed.

- **The 0x8001 byte single update.** It flagged a genuine handset whose OEM
  keystore mis-sizes the buffer. That is a defect in that device, not evidence
  about spoofing.
- **updateAad on a signing operation, and update after abort.** Neither is
  reachable through public API. Both need the keystore2 operation interface, so
  probing them would mean reflecting into non-public internals that move between
  releases.
- **A unique ID request.** `setUniqueIdIncluded` is `@hide`, `@TestApi` and
  `@UnsupportedAppUsage`, so it is a system-app call and the hidden API
  denylist blocks reflection at it.
- **An attestation challenge on a symmetric key.** `KeyGenParameterSpec`'s
  javadoc states that `generateKey()` throws `InvalidAlgorithmParameterException`
  in this case. Measured behaviour contradicts it: on API 34 both a Samsung TEE
  and the AOSP software keystore accepted the request with no exception at all.
  Implementing the documented rule would have flagged every device including a
  stock emulator, so the arm was dropped rather than shipped against a document
  nothing honours.

## Notes on best-effort checks

The root-manager package probe is best-effort by construction. KernelSU, SukiSU
Ultra and ReSukiSU all let the manager package name be set at build time, so a
miss is expected rather than a bug. The probe covers the default names only.

## Measured behaviour on a properly hidden device

The interesting case is not a carelessly rooted phone, it is one configured the
way current community guides describe. On the test device with the detector
added to the Magisk denylist, so Shamiko cleans its namespace, and with no
keystore spoofing module installed:

- The app's own mount table drops from 1479 lines to 162. Every mount rule goes
  silent: the tmpfs-over-system-partition candidates fall from 7 to 0, and the
  /adb bind that leaks a module name disappears. All remaining tmpfs mounts
  carry the genuine source "tmpfs".
- The whole native scan returns 0. Zygisk, Root Hider, property and artifact
  checks all report clean. CODE_INTEGRITY is the answer to this row, and it is an
  honest partial one: it verifies code rather than names, so a rename does not defeat
  it, but it only sees a hider that actually touches this process. Shamiko cleaning a
  namespace leaves no hook behind, so it stays silent here too. What it covers is the
  injection case, not the mount-hiding case.
- Key attestation still fires. The properties claim verifiedbootstate=green and
  flash.locked=1, while the genuine TEE attests a bootloader that is necessarily
  unlocked, and a root hider cannot reach what the TEE signs.

That is the whole argument for treating attestation as the load-bearing
unprivileged signal and the artifact checks as corroboration: against a
configured setup, the artifact checks contribute nothing and the attestation
contradiction contributes everything.

## Method

Every detection change is validated against two classes of device: genuine
hardware that must stay clean, and a configured bypass stack that must be
caught. A check that flags a genuine device is a bug and does not ship, per
SKILLS.md.

## Why five arms are computed but never flag

`ro.vendor.build.security_patch` is `vendor_security_patch_level_prop`, which
AOSP's sepolicy grants to `vendor_init`, `keystore` and `shell` only, while
`ro.build.version.security_patch` is `build_prop` and readable by every domain.
Measurement shows that is not the whole story: the app reads the vendor value as
empty on the Pixel 7a and the moto g04, and as `2024-09-01` on the Samsung,
whose vendor policy adds the grant AOSP does not. So the arm is live on some
vendors and dead on others, through no property of the device being examined. A
finding that fires on one vendor and cannot fire on another is not a finding, so
both vendor arms report only.

The absent-boot-patch arm is held for the opposite reason: all three devices
carry tag 719, so nothing in this population can show what a genuine device
missing it looks like. VTS requires the tag by default but ships a
`--skip_boot_pl_check` escape, so absence stays a readout until a device
without it is observed.

The month-precision arm is held because an OEM that tracks a partition at month
granularity is non-conforming rather than dishonest.

An attested boot hash that is all zeroes or not 32 bytes long reports rather
than flags. An earlier revision called it a contradiction, since
`ro.boot.vbmeta.digest` is readable by every SELinux domain and a conforming
implementation has no excuse. No measurement was available to show a genuine
device cannot produce it, so it was walked back.
