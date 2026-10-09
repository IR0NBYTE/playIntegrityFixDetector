package io.github.ir0nbyte.pifdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The boundary probe against the real keystore.
 *
 * The unit tests cover the decision table. What they cannot cover is whether
 * the contract this is built on actually holds on hardware, so these assert the
 * two KeyMint behaviours directly. A failure here is worth reading rather than
 * suppressing: either the device is serving fabricated records, or the arm is
 * built on a guarantee this implementation does not honour, and both of those
 * need a person.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreBoundaryInstrumentedTest {

    private val probe = KeystoreBoundaryProbe()

    /**
     * The arms have to have run. A probe that quietly skipped everything would
     * report clean for the wrong reason, which is how this codebase previously
     * shipped a dead obfuscation VM and two dead property literals.
     */
    @Test
    fun theArmsActuallyRan() {
        val observation = probe.observe()
        assertNotNull("the no-challenge arm did not run", observation.noChallenge)
        assertNotNull("the legal-challenge arm did not run", observation.legalChallenge)
        assertNotNull("the over-limit arm did not run", observation.overLimitChallenge)
    }

    /**
     * IKeyMintDevice::generateKey returns a single self-signed certificate when
     * no attestation is requested, and KeyMint returns that chain itself, so
     * this is the implementation's own answer.
     */
    @Test
    fun aNoChallengeKeyComesBackSelfSignedWithNoRecord() {
        val shape = probe.observe().noChallenge
            ?: return  // nothing to assert on a device that cannot generate one

        assertTrue("a no-challenge signing key must be self-signed", shape.selfSigned)
        assertFalse(
            "there was no challenge, so an attestation record cannot legitimately exist",
            shape.carriesAttestationRecord
        )
    }

    /**
     * Tag.aidl: "The challenge value may be up to 128 bytes. If the caller
     * provides a bigger challenge, INVALID_INPUT_LENGTH error should be
     * returned." Nothing in keystore2 enforces it, so the refusal comes from
     * KeyMint.
     */
    @Test
    fun theDocumentedMaximumIsAcceptedAndOneByteMoreIsRefused() {
        val observation = probe.observe()

        // A handset whose attestation keys were never provisioned refuses both
        // sizes, and then "the over-limit one was refused" proves nothing. Skip
        // rather than assert, so the test does not fail for a reason that has
        // nothing to do with the boundary.
        if (observation.legalChallenge?.accepted != true) return

        assertEquals(
            "a challenge one byte past the documented maximum should be refused",
            false,
            observation.overLimitChallenge?.accepted
        )
    }

    /** Which is to say: the probe is silent on this device. */
    @Test
    fun theProbeIsSilentOnThisDevice() {
        val verdict = probe.probe()
        assertEquals(
            "the boundary probe fired on this device: ${describe(verdict.reasons)}",
            0,
            verdict.mask
        )
    }

    /** Running twice must not leave a key behind or change the answer. */
    @Test
    fun theProbeIsRepeatable() {
        val first = probe.probe()
        val second = probe.probe()
        assertEquals(first.mask, second.mask)
        assertEquals(first.reasons, second.reasons)
    }

    private fun describe(reasons: List<Int>): String =
        ReasonCodes.describe(reasons).values.flatten().joinToString("; ")
}
