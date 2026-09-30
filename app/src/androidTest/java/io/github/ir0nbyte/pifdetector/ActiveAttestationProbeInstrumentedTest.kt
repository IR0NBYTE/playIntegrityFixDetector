package io.github.ir0nbyte.pifdetector

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

@RunWith(AndroidJUnit4::class)
class ActiveAttestationProbeInstrumentedTest {
    private val presentation
        get() = DeviceIdentity.fromRuntime(
            InstrumentationRegistry.getInstrumentation().targetContext
        )

    @Test
    fun probeNeverThrowsAndReturnsOnlyItsOwnFlag() {
        Log.i(DIAG_TAG, "presentation=$presentation")
        Log.i(
            DIAG_TAG,
            "presentsAsPhysicalHardware=" +
                DeviceIdentity.presentsAsPhysicalHardware(presentation)
        )
        for (passiveFlagged in listOf(false, true)) {
            val result = ActiveAttestationProbe().probe(passiveFlagged, presentation)
            Log.i(DIAG_TAG, "probe(passiveFlagged=$passiveFlagged) = 0x${result.toString(16)}")
            assertTrue(
                "probe must return 0, ATTEST_FORGERY or ATTEST_SOFTWARE, got 0x${result.toString(16)}",
                result == 0 ||
                    result == DetectionResult.DETECTION_ATTEST_FORGERY ||
                    result == DetectionResult.DETECTION_ATTEST_SOFTWARE
            )
        }
    }

    @Test
    fun passiveFlaggedNeverIncreasesTheActiveVerdict() {
        val loud = ActiveAttestationProbe().probe(false, presentation)
        val quiet = ActiveAttestationProbe().probe(true, presentation)
        Log.i(DIAG_TAG, "suppression: unsuppressed=0x${loud.toString(16)} suppressed=0x${quiet.toString(16)}")
        assertTrue(
            "suppressing anchoring must not add findings",
            quiet == 0 || quiet == loud
        )
    }

    @Test
    fun reportsAttestKeyProvocationCapability() {
        val pm = InstrumentationRegistry.getInstrumentation().targetContext.packageManager
        val advertised = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
        Log.i(DIAG_TAG, "sdk=${Build.VERSION.SDK_INT} attestKeyFeature=$advertised")

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            Log.i(DIAG_TAG, "provocationA=skipped (API < 31)")
            return
        }
        describeChain("provocationA") {
            KeyGenParameterSpec.Builder(ALIAS_A, KeyProperties.PURPOSE_ATTEST_KEY)
                .setAttestationChallenge(challenge())
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        }
    }

    @Test
    fun reportsAuthBoundProvocationCapability() {
        describeChain("provocationB") {
            KeyGenParameterSpec.Builder(
                ALIAS_B,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAttestationChallenge(challenge())
                .setDigests(KeyProperties.DIGEST_SHA512)
                .setUserAuthenticationRequired(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            60,
                            KeyProperties.AUTH_DEVICE_CREDENTIAL or
                                KeyProperties.AUTH_BIOMETRIC_STRONG
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(60)
                    }
                }
                .build()
        }
    }

    private fun describeChain(label: String, spec: () -> KeyGenParameterSpec) {
        val alias = if (label == "provocationA") ALIAS_A else ALIAS_B
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

            val gen = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            gen.initialize(spec())
            gen.generateKeyPair()

            val chain = (keyStore.getCertificateChain(alias) ?: emptyArray())
                .mapNotNull { it as? X509Certificate }
            val leaf = chain.firstOrNull()
            val ext = leaf?.getExtensionValue(AttestationAnalysis.ATTESTATION_OID)

            Log.i(DIAG_TAG, "$label=generated chainLen=${chain.size}")
            Log.i(DIAG_TAG, "$label leafSigAlg=${leaf?.sigAlgName}")
            Log.i(DIAG_TAG, "$label root=${chain.lastOrNull()?.subjectX500Principal?.name}")
            Log.i(
                DIAG_TAG,
                "$label anchored=" +
                    AttestationAnalysis.chainAnchorsToPinnedRoot(chain, AttestationRoots.pinnedRoots)
            )
            if (ext != null) {
                Log.i(
                    DIAG_TAG,
                    "$label tags 503=${AttestationAnalysis.hasHardwareEnforcedTag(ext, 503)} " +
                        "504=${AttestationAnalysis.hasHardwareEnforcedTag(ext, 504)} " +
                        "505=${AttestationAnalysis.hasHardwareEnforcedTag(ext, 505)}"
                )
                Log.i(
                    DIAG_TAG,
                    "$label authContradiction=" +
                        AttestationAnalysis.authRequirementContradiction(ext)
                )
            } else {
                Log.i(DIAG_TAG, "$label ext=absent (no attestation extension)")
            }
            keyStore.deleteEntry(alias)
        } catch (e: Exception) {
            Log.i(DIAG_TAG, "$label=unavailable: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun challenge() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        const val DIAG_TAG = "PIFD_PROBE_DIAG"
        const val ALIAS_A = "pifd_it_attestkey"
        const val ALIAS_B = "pifd_it_authbound"
    }
}
