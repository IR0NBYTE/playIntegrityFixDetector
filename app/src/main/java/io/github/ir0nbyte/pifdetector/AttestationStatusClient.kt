package io.github.ir0nbyte.pifdetector

import android.util.Log
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

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
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            parseRevokedSerials(body)
        } catch (e: Exception) {
            Log.w(TAG, "revocation fetch failed; failing safe", e)
            null
        } finally {
            conn?.disconnect()
        }
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
    }
}
