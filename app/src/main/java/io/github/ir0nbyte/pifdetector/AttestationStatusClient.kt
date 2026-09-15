package io.github.ir0nbyte.pifdetector

import android.util.Log
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

class AttestationStatusClient {
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

        const val MAX_BODY_BYTES = 1024 * 1024

        const val TOTAL_BUDGET_MS = 8000
    }
}
