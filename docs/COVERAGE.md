# Detection coverage

What each flag actually observes, whether it can fire from an unprivileged
untrusted_app, and what defeats it. This file exists because a check that
"exists" is not a check that "fires", and a README that implies otherwise is the
failure this project keeps auditing for.

Measured on a Pixel 7a (lynx), Android 15, Magisk 28.1 with Shamiko v1.2.1 and
Vector v2.2, no keystore spoofing module, unless a row says otherwise.

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
| TREAT_WHEEL | maps needle | Yes | In-process, genuinely fires | A renamed build |
| ATTEST_ANOMALY | chain signatures, CA issuers, root anchoring, challenge echo, RootOfTrust vs tamper, boot properties vs RootOfTrust | Yes | Fires on the test device: properties claim locked while the genuine Titan M2 reports the bootloader unlocked | A keystore simulator that also sanitizes the properties it contradicts |
| ATTEST_FORGERY | attest-key provocation, auth-bound SHA-512 provocation, self-signed single cert | Yes | Works. The tag-503 arm now fires on nothing current and is retained only for TEESimulator v3 and older | Simulators that honour setAttestKeyAlias and auth-bound keys |
| ATTEST_REVOKED | chain serials against Google's published revocation list, offline snapshot plus optional online refresh. Informational only: sets no detection bit | Yes | See the section below | A keybox not yet published as revoked, which is the normal case for a fresh rotation |
| ATTEST_CROSS_SOURCE | attested osPatchLevel and vendorPatchLevel against the device's own security-patch properties. The verifiedBootHash arm is computed and reported but does NOT drive the verdict | Yes | Silent on the test device, where all sources agree: 202412 vs 2024-12-05 and 202412 vs 2024-12-05. The boot-hash arm additionally requires ro.boot.vbmeta.hash_alg to be sha256 and a 64-hex-character digest; on any other configuration it does not run. It equals the attested hash on the Pixel 7a, but that equality is a bootloader and KeyMint implementation detail rather than a CDD guarantee, so it is held back until confirmed on non-Pixel hardware | A simulator that also rewrites the properties in the same pass |
| ATTEST_SOFTWARE | software-level attestation on a device presenting as production hardware with a declared hardware-backed keystore | Yes | Silent on the test device, whose chain is TrustedEnvironment and Google anchored | Presenting honestly as an emulator, which is also the legitimate case |
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
- **LISTED** (KNOWN_REVOKED): a serial is on the list. Rendered amber, counted as
  neither a pass nor a detection, with the batch-key caveat stated on the row.
- **UNVERIFIED** (UNVERIFIABLE): neither the snapshot nor the network could be
  consulted. Neither a pass nor a detection.
- **UNVERIFIED** (NOT_APPLICABLE): there was no Google-anchored chain, so there
  was nothing to look up. Shares the UNVERIFIED label, with its own row text.
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
would flag every honest user at once.

Snapshot cadence: regenerated by `tools/revocation/refresh_snapshot.py`, which
refuses to write on a short, malformed, or anomalously shrinking list.

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
  checks all report clean.
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
