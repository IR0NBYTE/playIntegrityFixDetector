package io.github.ir0nbyte.pifdetector

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The attested identity probe against the real keystore.
 *
 * The unit tests cover the decision table. What they cannot cover is whether
 * the contract it is built on actually holds on hardware, so these assert the
 * Tag.aidl rule directly: an identifier may appear only in a record whose
 * request asked for one, and this app asks for none in the ordinary request and
 * only the five device properties in the other. A failure here is worth reading
 * rather than suppressing, because either this keystore is volunteering
 * identifiers or the rule is not honoured by this implementation.
 */
@RunWith(AndroidJUnit4::class)
class AttestedIdentityInstrumentedTest {

    private val probe = AttestedIdentityProbe()

    /**
     * The arms have to have run. A probe that quietly skipped everything would
     * report clean for the wrong reason, which is how this codebase previously
     * shipped a dead obfuscation VM and two dead property literals.
     */
    @Test
    fun theArmsActuallyRan() {
        val observation = probe.observe()
        assertNotNull("the ordinary attestation arm did not run", observation.plain)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            assertNotNull(
                "the device-properties arm did not run on a device that has the setter",
                observation.withProperties
            )
        }
    }

    /**
     * Tag.aidl, on every identifier tag: "This field must be set only when
     * requesting attestation of the device's identifiers." This request asked
     * for none.
     */
    @Test
    fun anOrdinaryRecordCarriesNoIdentifier() {
        val plain = probe.observe().plain
            ?: return  // nothing to assert where the record could not be read

        assertEquals(
            "an ordinary attestation request asked for no identifier, so the record " +
                "should carry none: hardware ${plain.hardwareEnforced}, " +
                "software ${plain.softwareEnforced}",
            emptySet<Int>(),
            plain.all
        )
    }

    /**
     * Serial, IMEI, MEID and the second IMEI need READ_PRIVILEGED_PHONE_STATE
     * and the hidden setAttestationIds, so neither request could have asked for
     * them and neither answer may contain them.
     */
    @Test
    fun noRecordCarriesAPrivilegedIdentifier() {
        val observation = probe.observe()
        val records = listOfNotNull(observation.plain, observation.withProperties?.record)
        for (record in records) {
            assertEquals(
                "a record carried an identifier this app cannot request: ${record.all}",
                emptySet<Int>(),
                record.all.intersect(AttestedIdentity.PRIVILEGED_TAGS)
            )
        }
    }

    /**
     * The device-properties request has exactly two honest answers: refused, or
     * accepted with the identifiers vouched for by the secure environment that
     * signed the record. Anything else is what the probe reports.
     */
    @Test
    fun theDevicePropertiesRequestWasAnsweredHonestly() {
        val outcome = probe.observe().withProperties ?: return
        if (!outcome.accepted) return

        val record = outcome.record ?: return
        assertTrue(
            "the request was accepted, so the record must carry the identifiers: " +
                "hardware ${record.hardwareEnforced}, software ${record.softwareEnforced}",
            record.all.any { it in AttestedIdentity.DEVICE_PROPERTY_TAGS }
        )
    }

    /** Which is to say: the probe is silent on this device. */
    @Test
    fun theProbeIsSilentOnThisDevice() {
        val verdict = probe.probe()
        assertEquals(
            "the attested identity probe fired on this device: ${describe(verdict.reasons)}",
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
