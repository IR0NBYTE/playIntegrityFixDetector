# Detection improvement plan

Companion to docs/PLAN.md, scoped to one question: what should the PIF Detector
check that it does not check today, ranked by evidence from the live bypass
ecosystem (September 2026). Every item is a defensive signal for an unprivileged
untrusted_app. Ground rules from SKILLS.md still hold: a check earns a place only
if it is deterministic, distinguishing, and cannot false-positive on genuine
hardware; restore before you delete; test on a real build before a commit.

## What the field research changed

The bypass stack converged this quarter and the detector's assumptions need to
move with it.

- The keystore half is now a KeyMint simulator by default (TEESimulator-RS, or
  TEESimulator / OhMyKeymint), orchestrated by Specter or AlwaysStrong, not
  hand-built TrickyStore certificates. Community guides posted in the last week
  name the same stack: KernelSU-Next or Magisk, ReZygisk or Zygisk Next, PIF
  Inject or Fork, a KeyMint simulator, Specter, HMA-OSS, and a SuSFS kernel.
- The detector's own package class is on the standard hide list. The community
  HMA / Hide-My-Applist template ships with the detector ecosystem's packages
  pre-listed: Duck Detector, key attestation viewers, Securify, Hunter, Holmes,
  RootBeer, and RASP SDK class names are all there. Our package is not on that
  public list yet, but it will be added the moment it gets traction, so package
  visibility manipulation is itself a signal to design for now.
- Revocation checking has a measurable lag. The orchestration modules run their
  own revocation checks against Google's public status list before serving a
  keybox, and they mark internally-known-bad keyboxes as softbanned well before
  those serials appear in Google's public list. So a keybox the community already
  treats as burned can still be absent from the public revocation feed the
  detector queries. Revocation is necessary but not sufficient: it catches the
  widely-shared and already-listed, not the freshly-rotated. Treat a clean
  revocation result as "not known-bad", never as "genuine".
- SELinux and AVC-log spoofing are routine setup steps in current guides, not
  advanced tricks. Any detector signal that reads SELinux enforce state or its
  own audit events is being actively countered and cannot be trusted alone.
- Emulators and even unmodified Android Studio AVDs are reportedly passing
  STRONG. The software-attestation anchoring exemption is a real false-negative
  surface and needs the cross-checks below so "software-backed" is not a free
  pass.

## Confirmed feasible

The cross-process approach that PLAN.md Phase E left as a spike is feasible for an
unprivileged app: the peer detector runs its TEE and keystore-grant probes from a
service declared `android:isolatedProcess="true"` in its own data module, no root
required. That removes the main risk from the highest-value new signal below.

## Ranked detection work

### D1. Revocation as a first-class, fail-closed signal (highest value)

This is the one signal that still discriminates against a KeyMint simulator today,
and in the current detector it is opt-in and fails open.

- Default the check on. Ship a bundled snapshot of the revocation list as a
  gzipped asset with its fetch date, refreshed monthly by CI. Query the network
  only to supplement the snapshot.
- More than two outcomes: verified, listed, and the several ways a run can reach
    no verdict. See docs/COVERAGE.md for the shipped set. A
  Google-anchored chain that could be checked against neither the snapshot nor the
  network is unverifiable and renders as a warning with the snapshot date, never
  as a pass. Today the null path is a silent pass.
- Query both encodings. The list mixes decimal-keyed and hex-keyed serials;
  look each serial up in both, which the existing analysis code already does for
  the manual path.
- State the limitation in the UI and in COVERAGE.md: revocation catches
  known-bad keyboxes, and there is a lag between a keybox being burned in
  practice and appearing in the public list. It is a floor, not a ceiling.

### D2. Cross-source attestation consistency (does not depend on the network)

A KeyMint simulator makes each field internally consistent, but the fields it
attests still have to agree with sources on the device it does not control
together.

- Patch level: parse osPatchLevel, vendorPatchLevel and bootPatchLevel from the
  attestation extension and compare with the system and vendor security-patch
  properties, normalized to year-month. A simulator that changes only attestation
  drifts from the properties on most installs. Gate on a hardware-backed,
  Google-anchored chain. Validate against the genuine-device corpus first: some
  OEMs legitimately report vendor lagging system, and date formats differ across
  partitions.
- Verified-boot hash: compare the attested verifiedBootHash with the runtime
  vbmeta digest when both are present and the chain is hardware-backed and
  anchored. Current simulators keep these in sync deliberately, but an unlocked
  device driving an older module does not always, and the field guides carry a
  standard fix for exactly this mismatch, which tells you it is a live tell.
- Spike, verify readability first: attested KeyMint version against the vendor
  KeyMint HAL version. Confirm an untrusted app can read the VINTF manifest
  before building the probe.

### D3. Distribution-aware timing probe (behavioural, not artifact)

The peer detector's timing oracle measures attested vs non-attested key
operations; the counter-move on the bypass side pads the forged path to the mean
of real latency. The defensive answer is to measure the distribution, not the
mean.

- Pin to one core, generate interleaved pairs of attested and non-attested keys,
  record median ratio, spread, and direction consistency across pairs, not just
  the average. Padding to a mean leaves variance and skew intact.
- Calibrate thresholds on the genuine-device corpus, publish them in
  COVERAGE.md, and report the raw numbers in the export so a borderline result is
  auditable. Start as a warning, never a hard fail, until the corpus proves zero
  false positives.

### D4. Software-attestation exemption hardening

Because emulators and stock AVDs are passing, the anchoring exemption for
software-backed chains needs guards so it is not a free pass.

- When a chain reports software security level, cross-check the other device
  signals (the native emulator and property checks the engine already computes)
  and surface "software-backed attestation on a device that presents as physical
  hardware" as its own finding, distinct from a clean emulator or GSI.
- Keep genuine emulators, GSI and AOSP builds clean: those legitimately report
  software attestation and must not flag on the exemption alone.

### D5. Package-visibility manipulation as a signal

The hide layer works by controlling which packages an app can see. That control
is observable.

- Probe for the expected baseline of visible packages (a small set that any app
  should see) and flag when the visible set is implausibly filtered for an
  ordinary app, which is what per-app package hiding produces.
- Declare the queried packages in the manifest so the probe is not itself
  defeated by the visibility rules, exactly as the root-manager probe already
  requires. Keep this a low-weight corroborating signal, not a standalone verdict.

### D6. Refresh the artifact tables and honesty labels

Low value against a configured stack, free to keep current, and it stops the
README overclaiming.

- Update the privileged-path and module-name tables for the current wave
  (KeyMint simulators, current orchestration modules, current Zygisk
  implementations), each verified against the module's own install script before
  it is added.
- Keep every privileged-only or countered check labelled not-observable in the
  UI and excluded from the coverage count, per the existing honesty rule. Move
  the mount-namespace and boot-contradiction checks that cannot fire unprivileged
  into that bucket if they are not already there.

## Outcome (implemented 2026-09-30)

What landed, and what the evidence rejected. Every row was validated on a rooted
Pixel 7a (Magisk 28.1, Shamiko, Vector, genuine Titan M2) and, where relevant, on
a stock AVD and against TrickyStoreOSS v3.1.0.

| Item | Outcome | Evidence |
|---|---|---|
| D1 revocation | Landed, informational | Found and fixed a worse defect than this plan described: the probe returned on the first finding with revocation last, so on any device tripping an earlier check it never ran at all. Restructured into trust gates plus an accumulate phase. Both rows now populate in one run, and airplane mode answers from the bundled snapshot. Review then established that the outcome must NOT set a detection bit: batch keys are shared across a production run, so a stock handset from a leaked batch carries the same serial a spoofer does, and 26 entries are SOFTWARE_FLAW rather than compromise. It is reported on its own amber row instead |
| D2 cross-source | Landed, arms (a) and (b) | Patch level and verified boot hash compare cleanly. Silent on genuine hardware where all three sources agree |
| D2 (c) VINTF spike | Not implemented | /vendor/etc/vintf/manifest.xml is labelled vendor_configs_file. Reading it under run-as proves nothing, because runas_app is a different SELinux domain from untrusted_app |
| D3 timing | Rejected | Measured genuine median ratios of 4.04 to 6.10 on this device, so the statistic works. But an unpadded forgery is already caught cryptographically by anchoring, RootOfTrust and revocation, so timing adds no coverage against that adversary while carrying real false-positive risk on unmeasured SoCs. Not shipped |
| D4 software attestation | Landed | A stock AVD declares hardware_keystore and has a fully production-looking identity, so without the virtual-device guard this check would flag every emulator. With it, the emulator probe returns 0x0 |
| D5 package visibility | Held | The planned baseline-of-visible-packages framing is not implementable: a genuine Pixel app sees 124 of 354 packages and com.android.packageinstaller does not exist on the device. Only the self-contradiction form (listed as visible, then denied on lookup) is viable, and it needs its own spec |
| D6 part 1 artifact table | Partly | Added only the two root-manager packages that could be justified. The module-path additions were rejected: they feed privileged-only flags that cannot fire unprivileged |
| D6 part 2 honesty | Landed | detectMountNS replaced by an in-process mountinfo probe that fires on this device today. Three README overclaims corrected, including a SELinux check the README described that never existed in the engine |

Measured effect: observable checks went from 11 to 14, and the detector reports 3
of 14 on the rooted test device, all three correct.

## Sequencing

1. D1 first. It is the smallest change with the highest live value and it closes
   a fail-open hole that exists today.
2. D2 next: patch-level and boot-hash consistency are cheap, offline, and hard to
   satisfy together with a changed-attestation-only module.
3. D4 and D5 alongside D2: small, corroborating, and they address the
   false-negative surface the emulator reports exposed.
4. D3 after the corpus exists. It is the strongest behavioural signal but needs
   calibration data before it can ship without false positives.
5. D6 continuously, one verified entry at a time.

## Verification

Every item runs against the PLAN.md matrix before its commit: the genuine-device
rows must stay clean, the configured-stack rows must be caught by the signal under
test, and each change ends in explicit commit approval after the test evidence is
shown. A detection change that flags a genuine device is a bug and does not ship.

## Explicitly not doing

- No operational keybox handling of any kind. The detector reads a serial from a
  chain and checks it against Google's published revocation list. It never
  fetches, stores, validates-for-use, or catalogs keyboxes.
- No new module-name needles for privileged-only flags. They cannot fire on a
  real install and the names churn faster than a release.
- No SELinux enforce-state or audit-log signal as a primary check, since both are
  routinely spoofed in the current stack.
