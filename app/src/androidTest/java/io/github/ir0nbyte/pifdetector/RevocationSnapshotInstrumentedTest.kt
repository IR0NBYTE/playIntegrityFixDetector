package io.github.ir0nbyte.pifdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The only test that proves asset packaging, the noCompress rule and the parser
 * agree inside a real APK. A JVM test cannot catch a snapshot that AGP deflated
 * a second time.
 */
@RunWith(AndroidJUnit4::class)
class RevocationSnapshotInstrumentedTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun shippedAssetParsesOnDevice() {
        val snapshot = RevocationSnapshotLoader.load(context)
        assertNotNull("bundled revocation snapshot failed to load or parse", snapshot)
        assertTrue(
            "snapshot holds too few entries: ${snapshot!!.serials.size}",
            snapshot.serials.size > 1000
        )
        assertTrue(
            "unexpected fetched date: ${snapshot.fetchedDate}",
            Regex("^\\d{4}-\\d{2}-\\d{2}$").matches(snapshot.fetchedDate)
        )
    }

    @Test
    fun shippedAssetIsUsableAsARevocationSource() {
        val snapshot = RevocationSnapshotLoader.load(context)
        assertNotNull(snapshot)
        val listedSerial = snapshot!!.serials.first()

        val status = RevocationChecker.evaluate(listOf(listedSerial), snapshot, null)
        assertEquals(RevocationOutcome.KNOWN_REVOKED, status.outcome)
        assertEquals(snapshot.fetchedDate, status.snapshotDate)
    }

    @Test
    fun unlistedSerialAgainstShippedAssetIsVerified() {
        val snapshot = RevocationSnapshotLoader.load(context)
        assertNotNull(snapshot)
        // A value no real certificate serial can take, so it cannot be listed.
        val status = RevocationChecker.evaluate(listOf("0".repeat(16)), snapshot, null)
        assertEquals(RevocationOutcome.VERIFIED, status.outcome)
    }

    @Test
    fun loaderIsStableAcrossCalls() {
        val first = RevocationSnapshotLoader.load(context)
        val second = RevocationSnapshotLoader.load(context)
        assertNotNull(first)
        assertTrue("loader must cache and return the same instance", first === second)
    }
}
