package io.github.ir0nbyte.pifdetector

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The StrongBox probe against the real keystore.
 *
 * The unit tests cover the decision table. What they cannot cover is whether
 * the device actually answers the StrongBox question the way keystore2 and the
 * framework say it must, so these assert it directly. A failure here is worth
 * reading rather than suppressing: either the device is contradicting itself
 * about having a secure element, or the arm rests on a guarantee this
 * implementation does not honour, and both of those need a person.
 */
@RunWith(AndroidJUnit4::class)
class StrongBoxInstrumentedTest {

    private val probe = StrongBoxProbe()
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * The arms have to have run. A probe that quietly skipped everything would
     * report clean for the wrong reason, which is how this codebase previously
     * shipped a dead obfuscation VM and two dead property literals.
     */
    @Test
    fun theArmsActuallyRan() {
        val observation = probe.observe(context)

        assertNotNull("the feature list could not be read", observation.featureDeclared)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            assertNotNull("the StrongBox request did not run", observation.availability)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            assertNotNull(
                "the keystore's own label on the ordinary key was not read",
                observation.ordinaryKeyLevel
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            assertNotNull("the AES size arm did not run", observation.aes192)
        }
    }

    /**
     * The guard against a dead arm, and the only part of the AES size
     * restriction a bench without a secure element can verify.
     *
     * NOT_ATTEMPTED means the framework rejected this probe's own parameter
     * spec before the keystore saw it, which would leave the arm silent
     * forever on the devices that matter. Anything else means the request was
     * well formed and reached the keystore, whatever the keystore then said.
     */
    @Test
    fun theAesRequestIsWellFormedAndReachesTheKeystore() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return

        assertNotEquals(
            "the AES arm's request never reached the keystore, so the arm is dead",
            StrongBoxCheck.AesOutcome.NOT_ATTEMPTED,
            probe.observe(context).aes192
        )
    }

    /**
     * On a device with a secure element, IKeyMintDevice.aidl requires the 192
     * bit key to be refused. Skipped where there is no StrongBox, because then
     * the request is turned away for a different reason entirely.
     */
    @Test
    fun aSecureElementRefusesTheSizeItMustRefuse() {
        val observation = probe.observe(context)
        if (observation.availability != StrongBoxCheck.Availability.SERVED) return

        assertEquals(
            "a StrongBox must only support 128 and 256 bit AES keys",
            StrongBoxCheck.AesOutcome.REFUSED,
            observation.aes192
        )
    }

    /**
     * Not INCONCLUSIVE. keystore2 either has a KeyMint instance registered at
     * that security level or it does not, and the request carries no
     * attestation challenge precisely so that nothing else can make it fail.
     */
    @Test
    fun theKeystoreGivesADefiniteAnswerAboutStrongBox() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return

        assertNotEquals(
            "the StrongBox request failed for a reason other than the hardware " +
                "being absent, so this device cannot witness the arms that " +
                "depend on that answer",
            StrongBoxCheck.Availability.INCONCLUSIVE,
            probe.observe(context).availability
        )
    }

    /**
     * The cross-check itself, on hardware. The feature declaration and the
     * keystore have to agree about whether the secure element is there.
     */
    @Test
    fun theFeatureDeclarationAgreesWithWhatTheKeystoreServes() {
        val observation = probe.observe(context)
        val availability = observation.availability ?: return

        if (availability == StrongBoxCheck.Availability.SERVED) {
            assertEquals(
                "the keystore served a StrongBox key on a device that declares none",
                true,
                observation.featureDeclared
            )
        }
        if (observation.featureDeclared == false) {
            assertNotEquals(
                "this device declares no StrongBox, so it must not serve one",
                StrongBoxCheck.Availability.SERVED,
                availability
            )
        }
    }

    /**
     * The airtight half: once keystore2 has said there is no StrongBox
     * instance, nothing else on the device may come back labelled StrongBox.
     */
    @Test
    fun nothingClaimsStrongBoxWhereTheKeystoreHasNone() {
        val observation = probe.observe(context)
        if (observation.availability != StrongBoxCheck.Availability.UNAVAILABLE) return

        assertNotEquals(
            "the keystore labelled an ordinary key StrongBox after saying it has none",
            AttestationAnalysis.SECURITY_LEVEL_STRONGBOX,
            observation.ordinaryKeyLevel
        )
        assertEquals(
            "an attestation record claimed StrongBox after the keystore said it has none",
            false,
            observation.ordinaryRecord?.claimsStrongBox ?: false
        )
    }

    /** A record this probe provoked has to be readable, or it proves nothing. */
    @Test
    fun theRecordThisProbeProvokedIsReadable() {
        val record = probe.observe(context).ordinaryRecord ?: return

        assertNotNull("attestationSecurityLevel did not parse", record.attestationLevel)
        assertNotNull("keyMintSecurityLevel did not parse", record.keyMintLevel)
        assertTrue(
            "an attested key should report a hardware or software level, not ${record.attestationLevel}",
            record.attestationLevel in AttestationAnalysis.SECURITY_LEVEL_SOFTWARE..
                AttestationAnalysis.SECURITY_LEVEL_STRONGBOX
        )
    }

    /** Which is to say: the probe is silent on this device. */
    @Test
    fun theProbeIsSilentOnThisDevice() {
        val verdict = probe.probe(context)
        assertEquals(
            "the StrongBox probe fired on this device: ${describe(verdict.reasons)}",
            0,
            verdict.mask
        )
    }

    /** Running twice must not leave a key behind or change the answer. */
    @Test
    fun theProbeIsRepeatable() {
        val first = probe.probe(context)
        val second = probe.probe(context)
        assertEquals(first.mask, second.mask)
        assertEquals(first.reasons, second.reasons)
    }

    private fun describe(reasons: List<Int>): String =
        ReasonCodes.describe(reasons).values.flatten().joinToString("; ")
}
