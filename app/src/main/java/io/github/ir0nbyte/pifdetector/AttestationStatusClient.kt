package io.github.ir0nbyte.pifdetector

import android.util.Log
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

class AttestationStatusClient {
    /**
     * Returns the revoked serial set, or null when the source was unusable.
     *
     * Null and empty mean very different things here. An empty set would answer
     * "not listed" for every serial, so a captive portal or a proxy error page
     * that returns HTTP 200 with the wrong body must be discarded entirely
     * rather than merged in as a clean result.
     */
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
            val parsed = parseRevokedSerials(body) ?: return null
            if (parsed.size < MIN_LIVE_ENTRIES) {
                Log.w(TAG, "revocation response held ${parsed.size} entries; discarding as unusable")
                return null
            }
            parsed
        } catch (e: Exception) {
            Log.w(TAG, "revocation fetch failed; source treated as unavailable", e)
            null
        } finally {
            conn?.disconnect()
        }
    }

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

    internal companion object {
        const val TAG = "AttestationStatus"
        const val STATUS_URL = "https://android.googleapis.com/attestation/status"

        const val TIMEOUT_MS = 3000

        const val MAX_BODY_BYTES = 1024 * 1024

        const val TOTAL_BUDGET_MS = 5000

        /** The published list has held well over a thousand entries for years. */
        const val MIN_LIVE_ENTRIES = 500

        private val SERIAL_REGEX = Regex("^[0-9a-f]{8,64}$")

        /**
         * Returns null for any body that is not a usable revocation list.
         *
         * Kept free of Android APIs so it is unit testable on the JVM; the
         * caller does the logging.
         */
        internal fun parseRevokedSerials(json: String): Set<String>? {
            val entries = try {
                JSONObject(json).optJSONObject("entries")
            } catch (_: Exception) {
                null
            } ?: return null

            if (entries.length() == 0) return null

            val out = HashSet<String>()
            var malformed = 0
            val keys = entries.keys()
            while (keys.hasNext()) {
                val serial = keys.next()
                val status = entries.optJSONObject(serial)?.optString("status").orEmpty()
                if (status != "REVOKED" && status != "SUSPENDED") continue
                val lowered = serial.lowercase()
                // The offline snapshot rejects a malformed serial outright; the
                // live path must not be laxer, or a short key such as "1" could
                // match a genuine chain's decimal lookup key.
                if (!SERIAL_REGEX.matches(lowered)) { malformed++; continue }
                out.add(lowered)
            }
            // A body whose shape we do not recognise is not a revocation list.
            if (malformed > out.size / 10) return null
            return out
        }
    }
}
