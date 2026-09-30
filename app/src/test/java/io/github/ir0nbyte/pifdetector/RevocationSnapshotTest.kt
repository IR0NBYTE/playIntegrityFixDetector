package io.github.ir0nbyte.pifdetector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

/**
 * The parser is deliberately all or nothing. A partially read snapshot would
 * answer "not listed" for serials it never loaded, so every defect must yield
 * null rather than a short set.
 */
class RevocationSnapshotTest {

    private fun gzip(text: String): ByteArrayInputStream {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(text.toByteArray(Charsets.UTF_8)) }
        return ByteArrayInputStream(out.toByteArray())
    }

    private fun snapshotText(
        version: String = "# pifd-revocation-snapshot v1",
        fetched: String = "2026-09-30",
        declared: Int? = null,
        serials: List<String> = listOf(
            "5cb838f1fe157a85",
            "10023936558530442420",
            "ffb61c8e39ac7c26684d2ed1077ddd21",
        ),
        lineEnding: String = "\n",
    ): String {
        val count = declared ?: serials.size
        val lines = mutableListOf(
            version,
            "# source: https://android.googleapis.com/attestation/status",
            "# fetched: $fetched",
            "# last-modified: Tue, 29 Sep 2026 15:58:00 GMT",
            "# entries: $count",
        )
        lines.addAll(serials)
        return lines.joinToString(lineEnding) + lineEnding
    }

    @Test
    fun parsesWellFormedSnapshot() {
        val snapshot = RevocationSnapshot.parse(gzip(snapshotText()), 1)
        assertNotNull(snapshot)
        assertEquals("2026-09-30", snapshot!!.fetchedDate)
        assertEquals(3, snapshot.serials.size)
        assertTrue(snapshot.serials.contains("5cb838f1fe157a85"))
    }

    @Test
    fun rejectsWrongVersionLine() {
        val text = snapshotText(version = "# pifd-revocation-snapshot v2")
        assertNull(RevocationSnapshot.parse(gzip(text), 1))
    }

    @Test
    fun rejectsDeclaredCountMismatch() {
        assertNull(RevocationSnapshot.parse(gzip(snapshotText(declared = 4)), 1))
    }

    @Test
    fun rejectsUppercaseSerial() {
        val text = snapshotText(serials = listOf("5CB838F1FE157A85"))
        assertNull(RevocationSnapshot.parse(gzip(text), 1))
    }

    @Test
    fun rejectsNonHexSerial() {
        val text = snapshotText(serials = listOf("5cb838f1fe157g85"))
        assertNull(RevocationSnapshot.parse(gzip(text), 1))
    }

    @Test
    fun rejectsMalformedFetchedDate() {
        assertNull(RevocationSnapshot.parse(gzip(snapshotText(fetched = "2026-9-30")), 1))
    }

    @Test
    fun rejectsZeroEntries() {
        val text = snapshotText(serials = emptyList(), declared = 0)
        assertNull(RevocationSnapshot.parse(gzip(text), 1))
    }

    @Test
    fun rejectsTruncatedGzip() {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(snapshotText().toByteArray(Charsets.UTF_8)) }
        val bytes = out.toByteArray()
        val truncated = bytes.copyOfRange(0, bytes.size - 20)
        assertNull(RevocationSnapshot.parse(ByteArrayInputStream(truncated), 1))
    }

    @Test
    fun rejectsNonGzipGarbage() {
        assertNull(RevocationSnapshot.parse(ByteArrayInputStream("not a gzip".toByteArray()), 1))
    }

    @Test
    fun rejectsOversizeSnapshot() {
        val many = (0 until 50_001).map { "%016x".format(it) }
        assertNull(RevocationSnapshot.parse(gzip(snapshotText(serials = many)), 1))
    }

    /**
     * A snapshot far smaller than the published list is truncated. Answering
     * "not listed" from it would be a confident wrong answer.
     */
    @Test
    fun rejectsSnapshotBelowTheMinimumEntryFloor() {
        val few = (0 until 10).map { "%016x".format(it) }
        assertNull(RevocationSnapshot.parse(gzip(snapshotText(serials = few))))
    }

    @Test
    fun acceptsSnapshotAtTheMinimumEntryFloor() {
        val enough = (0 until RevocationSnapshot.MIN_ENTRIES).map { "%016x".format(it) }
        val snapshot = RevocationSnapshot.parse(gzip(snapshotText(serials = enough)))
        assertNotNull(snapshot)
        assertEquals(RevocationSnapshot.MIN_ENTRIES, snapshot!!.serials.size)
    }

    @Test
    fun crlfLineEndingsParseIdentically() {
        val lf = RevocationSnapshot.parse(gzip(snapshotText(lineEnding = "\n")), 1)
        val crlf = RevocationSnapshot.parse(gzip(snapshotText(lineEnding = "\r\n")), 1)
        assertNotNull(crlf)
        assertEquals(lf, crlf)
    }
}
