package io.github.ir0nbyte.pifdetector

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.InputStream
import java.util.zip.GZIPInputStream

// RevocationSnapshot itself stays free of Android APIs so the parser is unit
// testable on the JVM. Logging lives in the loader below, which already needs a
// Context.

/**
 * Parser for the bundled offline copy of Google's revocation list.
 *
 * The format is gzip over UTF-8 text: a header of '#' prefixed lines, then one
 * lowercase hex serial per line. Parsing is all or nothing. A partially read
 * snapshot would answer "not listed" for serials it simply never loaded, which
 * is worse than having no snapshot at all, so every defect returns null.
 */
object RevocationSnapshot {
    data class Snapshot(val fetchedDate: String, val serials: Set<String>)

    private const val VERSION_LINE = "# pifd-revocation-snapshot v1"
    private const val FETCHED_PREFIX = "# fetched: "
    private const val ENTRIES_PREFIX = "# entries: "
    private const val MAX_ENTRIES = 50_000

    /**
     * A snapshot far smaller than the published list is a truncated or partial
     * asset. Answering "not listed" from it would be a confident wrong answer,
     * so it is rejected and the outcome becomes UNVERIFIABLE instead.
     */
    internal const val MIN_ENTRIES = 500

    private val DATE_REGEX = Regex("^\\d{4}-\\d{2}-\\d{2}$")
    private val SERIAL_REGEX = Regex("^[0-9a-f]{8,64}$")

    fun parse(input: InputStream): Snapshot? = parse(input, MIN_ENTRIES)

    /** minEntries is injectable so tests can target the floor explicitly. */
    internal fun parse(input: InputStream, minEntries: Int): Snapshot? {
        return try {
            parseOrThrow(input, minEntries)
        } catch (_: Throwable) {
            // Any defect means the snapshot is unusable, never partially trusted.
            null
        }
    }

    private fun parseOrThrow(input: InputStream, minEntries: Int): Snapshot? {
        GZIPInputStream(input).bufferedReader().use { reader ->
            if (reader.readLine()?.trimEnd('\r') != VERSION_LINE) return null

            var fetchedDate: String? = null
            var declaredCount: Int? = null
            var line = reader.readLine()
            while (line != null && line.startsWith("#")) {
                val header = line.trimEnd('\r')
                when {
                    header.startsWith(FETCHED_PREFIX) ->
                        fetchedDate = header.removePrefix(FETCHED_PREFIX).trim()
                    header.startsWith(ENTRIES_PREFIX) ->
                        declaredCount = header.removePrefix(ENTRIES_PREFIX).trim().toIntOrNull()
                }
                line = reader.readLine()
            }

            if (fetchedDate == null || !DATE_REGEX.matches(fetchedDate)) return null
            val expected = declaredCount ?: return null
            if (expected < minEntries || expected > MAX_ENTRIES) return null

            val serials = readSerials(reader, line) ?: return null
            if (serials.size != expected) return null

            return Snapshot(fetchedDate, serials)
        }
    }

    /** Returns null on the first malformed serial, so a bad asset is never partially trusted. */
    private fun readSerials(reader: BufferedReader, firstLine: String?): Set<String>? {
        val serials = HashSet<String>()
        var line = firstLine
        while (line != null) {
            val serial = line.trimEnd('\r')
            if (serial.isNotEmpty()) {
                if (!SERIAL_REGEX.matches(serial)) return null
                if (serials.size >= MAX_ENTRIES) return null
                serials.add(serial)
            }
            line = reader.readLine()
        }
        return serials
    }
}

/** Loads and caches the snapshot packaged in the APK's assets. */
object RevocationSnapshotLoader {
    private const val TAG = "RevocationSnapshot"
    const val ASSET_NAME = "revocation_snapshot.bin"

    @Volatile
    private var cached: RevocationSnapshot.Snapshot? = null

    @Volatile
    private var attempted = false

    fun load(context: Context): RevocationSnapshot.Snapshot? {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            if (attempted) return null
            attempted = true
            val parsed = try {
                context.assets.open(ASSET_NAME).use { RevocationSnapshot.parse(it) }
            } catch (e: Throwable) {
                Log.w(TAG, "bundled snapshot could not be opened", e)
                null
            }
            cached = parsed
            return parsed
        }
    }
}
