package io.github.ir0nbyte.pifdetector

import android.util.Log
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/*
 * Fetches Google's attestation key revocation status list (check 1d).
 *
 * The list holds ONLY bad serials, keyed by lowercase-hex serial:
 *   { "entries": { "<serial>": { "status": "REVOKED|SUSPENDED", ... } } }
 * Presence of a chain's serial => revoked/suspended keybox. This is the only
 * signal that catches generation-mode spoofers (a leaked-but-real keybox whose
 * chain is otherwise cryptographically valid against a genuine Google root).
 *
 * Runtime/network only -- NOT unit-testable here. Every failure (offline,
 * timeout, non-200, malformed JSON, exception) returns null so the caller
 * fails safe (no flag). The pure serial-comparison logic lives in
 * AttestationAnalysis.anyCertRevoked and IS unit-tested.
 */
class AttestationStatusClient {

    /* Returns the set of revoked/suspended serials, or null on any failure. */
    fun fetchRevokedSerials(): Set<String>? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(STATUS_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                requestMethod = "GET"
            }
            if (conn.responseCode != HttpURLConnection.HTTP_OK) return null
            if (conn.contentLength > MAX_BODY_BYTES) return null
            val body = readBounded(conn) ?: return null
            parseRevokedSerials(body)
        } catch (e: Exception) {
            Log.w(TAG, "revocation fetch failed; failing safe", e)
            null
        } finally {
            conn?.disconnect()
        }
    }

    /*
     * Read the response body with a hard size cap and a wall-clock deadline.
     *
     * readTimeout bounds the gap between reads, not the total transfer, and
     * readText() has no size limit at all. This app exists to run on devices
     * where someone has root, and root owns /etc/hosts and the user CA store,
     * so android.googleapis.com can be pointed at a local server that drips
     * bytes forever. That produced an OutOfMemoryError on the worker thread,
     * which the probe reports as no anomaly -- turning a detection into a
     * silent pass. Returns null if either bound is hit.
     */
    private fun readBounded(conn: HttpURLConnection): String? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(TOTAL_BUDGET_MS.toLong())
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        conn.inputStream.use { stream ->
            while (true) {
                if (System.nanoTime() > deadline) return null
                val n = stream.read(buf)
                if (n < 0) break
                if (out.size() + n > MAX_BODY_BYTES) return null
                out.write(buf, 0, n)
            }
        }
        return out.toString(Charsets.UTF_8.name())
    }

    /*
     * Parse the status JSON into the set of serials whose status is REVOKED or
     * SUSPENDED. org.json is an Android-runtime class (stubbed in plain JVM
     * unit tests), so this stays here rather than in the unit-tested
     * AttestationAnalysis. Returns an empty set if there are no entries.
     */
    private fun parseRevokedSerials(json: String): Set<String> {
        val entries = JSONObject(json).optJSONObject("entries") ?: return emptySet()
        val out = HashSet<String>()
        val keys = entries.keys()
        while (keys.hasNext()) {
            val serial = keys.next()
            val status = entries.optJSONObject(serial)?.optString("status").orEmpty()
            if (status == "REVOKED" || status == "SUSPENDED") {
                out.add(serial.lowercase())
            }
        }
        return out
    }

    private companion object {
        const val TAG = "AttestationStatus"
        const val STATUS_URL = "https://android.googleapis.com/attestation/status"
        const val TIMEOUT_MS = 4000

        /* Google's list is a few tens of KB; 1 MB is generous headroom. */
        const val MAX_BODY_BYTES = 1024 * 1024

        /* Whole-transfer budget, independent of the per-read timeout. */
        const val TOTAL_BUDGET_MS = 8000
    }
}
