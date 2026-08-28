package io.github.ir0nbyte.pifdetector

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/*
 * In-app Android Key Attestation probe (Priority 1, May 2026).
 *
 * The 2026 STRONG-integrity bypass stack (TrickyStore, TrickyStoreOSS,
 * TEESimulator, keybox spoofers, PIF-NEXT) attacks hardware key attestation --
 * a surface the native engine never exercises. This probe generates an
 * attested EC key in AndroidKeyStore and runs these low-false-positive checks
 * (decision/parse logic lives in AttestationAnalysis so it can be unit-tested):
 *
 *  1a. Chain signature validation -- leaf-hacking spoof modes (the default on
 *      the many TEE-broken devices) mutate the real TEE leaf's attestation
 *      extension, breaking the issuer's signature over it. A cryptographically
 *      broken chain => spoof.
 *  Anti-replay. The attestation must echo the random challenge nonce we passed;
 *      a cached/replayed cert won't carry it => spoof.
 *  1b. Attestation-vs-device contradiction -- spoofers force the attestation
 *      RootOfTrust to deviceLocked=true / verifiedBootState=Verified. If the
 *      attestation claims a locked/verified device while the native engine's
 *      own bitmask already proves tampering (root hider), that contradiction
 *      => spoof.
 *  1c. Root anchoring -- the chain must terminate at a genuine, pinned Google
 *      attestation root (see AttestationRoots). A signature-valid chain that
 *      does not anchor to a Google root is a software/fake-keybox spoof.
 *  1d. Revocation (opt-in) -- for a Google-anchored chain, when the user has
 *      enabled the revocation setting, each cert serial is checked against
 *      Google's status list to catch leaked-but-revoked real keyboxes. This is
 *      the ONLY check that touches the network; it is off by default.
 *
 * FAIL SAFE: every failure mode (no AndroidKeyStore, attestation unsupported,
 * no/short chain, parse failure, unrecognised root, offline revocation fetch,
 * any exception) returns 0. Absence of attestation must never flag -- old/AOSP
 * devices legitimately lack it -- so only a positively invalid, contradictory,
 * unanchored, or revoked chain sets the bit. Note 1a uses X509Certificate.verify
 * (signature only), never checkValidity(), so an expired-but-intact chain is not
 * treated as a spoof.
 */
class KeyAttestationProbe {

    private val statusClient = AttestationStatusClient()

    private class AttestedKey(val chain: List<X509Certificate>, val challenge: ByteArray)

    /*
     * Returns DETECTION_ATTEST_ANOMALY if attestation is present and proven
     * invalid/contradictory, else 0. `nativeBitmask` is the native engine's
     * result -- used to derive whether the device is independently known to be
     * tampered (for the 1b contradiction check). Never throws.
     */
    fun probe(nativeBitmask: Int, revocationEnabled: Boolean): Int {
        return try {
            val attested = generateAttestedChain() ?: return 0
            val chain = attested.chain
            if (chain.isEmpty()) return 0

            /*
             * 1a: cryptographic chain validation, and 1a': every issuer in the
             * chain must actually be a CA.
             *
             * Both run FIRST, before a single byte of the attestation extension
             * is parsed. The extension is written by whoever is spoofing, and
             * the parsers below are the only attacker-driven code here, so the
             * two checks that need nothing from it are the two that must not be
             * reachable-around.
             *
             * The CA check is what stops a chain that passes 1a and 1c anyway:
             * a genuine attested key from a real device is an end-entity cert
             * whose private key the attacker holds, so they can sign a forged
             * leaf with it and hand back a chain that verifies link by link and
             * terminates at a real Google root.
             */
            if (AttestationAnalysis.chainSignaturesBroken(chain)) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }
            if (AttestationAnalysis.chainHasNonCaIssuer(chain)) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            val extValue = chain[0].getExtensionValue(AttestationAnalysis.ATTESTATION_OID)
                ?: return 0  // no attestation extension -> not an attested key, don't flag

            /*
             * A Software-level chain is signed by the public AOSP software
             * attestation key, which is deliberately not among the pinned roots.
             * Anchoring therefore fails for it on clean emulators, GSI images
             * and AOSP builds, and flagging that would contradict the rule at
             * the top of this file that absence of attestation must never flag.
             * Unknown level (null) keeps the old behaviour and still anchors.
             */
            val softwareBacked =
                AttestationAnalysis.parseAttestationSecurityLevel(extValue) ==
                    AttestationAnalysis.SECURITY_LEVEL_SOFTWARE

            // 1c: anchor the (signature-valid) chain to a genuine Google root.
            // A chain that is internally self-consistent but does NOT terminate
            // at a pinned Google root is a fake-root spoof. chainAnchorsToPinnedRoot
            // is fail-safe: any inconclusive case returns true, so only a chain
            // proven unanchored flags.
            val googleAnchored =
                AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            if (!softwareBacked && !googleAnchored) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            // Anti-replay: the attestation must echo the nonce we just generated.
            val challenge = AttestationAnalysis.parseAttestationChallenge(extValue)
            if (AttestationAnalysis.challengeMismatch(challenge, attested.challenge)) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            // 1b: attestation-vs-device contradiction.
            val rot = AttestationAnalysis.parseRootOfTrust(extValue)
            if (AttestationAnalysis.isBootContradiction(rot, deviceTampered(nativeBitmask))) {
                return DetectionResult.DETECTION_ATTEST_ANOMALY
            }

            // 1d: revocation. Gated behind the user-visible setting (OFF by
            // default -> app stays network-silent unless the user opts in), and
            // only reached for a chain that anchors to a genuine Google root
            // (so the serials we query are actually Google's). Catches
            // generation-mode spoofers using a leaked-but-revoked real keybox.
            // Network call; bounded + fail-safe on every error path.
            if (revocationEnabled && googleAnchored) {
                val revoked = statusClient.fetchRevokedSerials()
                if (revoked != null) {
                    val serials =
                        chain.flatMap { AttestationAnalysis.serialLookupKeys(it.serialNumber) }
                    if (AttestationAnalysis.anyCertRevoked(serials, revoked)) {
                        return DetectionResult.DETECTION_ATTEST_ANOMALY
                    }
                }
            }

            0
        } catch (e: Throwable) {
            Log.w(TAG, "attestation probe failed; failing safe", e)
            0
        } finally {
            deleteKeyQuietly()
        }
    }

    /*
     * Gate for the 1b contradiction: the device must be proven tampered by a
     * signal that is HARD-incompatible with a genuine dm-verity Verified boot.
     * We use DETECTION_ROOT_HIDER only -- OverlayFS / mount-namespace divergence
     * on /system means the system partition is actively modified at runtime,
     * which a true Verified boot cannot coexist with. A real hardware
     * attestation on such a device reports unlocked/unverified, so an attestation
     * that instead claims locked/Verified is provably spoofed.
     *
     * Deliberately EXCLUDES:
     *  - DETECTION_ZYGISK: can be set merely by a root-manager APK being
     *    installed (PackageManager probe) on an otherwise-clean device.
     *  - DETECTION_BOOTLOADER: isBootloaderUnlocked() also trips on
     *    sys.oem_unlock_allowed (the dev-options TOGGLE, which can be on while
     *    the bootloader stays physically locked + verified-boot green),
     *    ro.debuggable and ro.secure (userdebug/eng builds). None of those mean
     *    verified boot is actually broken, so feeding them into a contradiction
     *    would flag clean devices. The standalone BOOTLOADER bit still surfaces
     *    those conditions to the user on their own.
     */
    private fun deviceTampered(nativeBitmask: Int): Boolean {
        return (nativeBitmask and DetectionResult.DETECTION_ROOT_HIDER) != 0
    }

    private fun generateAttestedChain(): AttestedKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        // Clean up any leftover from a previous interrupted run.
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)

        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        generator.generateKeyPair()

        val raw = keyStore.getCertificateChain(KEY_ALIAS) ?: return null
        return AttestedKey(raw.mapNotNull { it as? X509Certificate }, challenge)
    }

    private fun deleteKeyQuietly() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {
            // best-effort cleanup
        }
    }

    private companion object {
        const val TAG = "KeyAttestationProbe"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "pifd_attest_probe"
    }
}
