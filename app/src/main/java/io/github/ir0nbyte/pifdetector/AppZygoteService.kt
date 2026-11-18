package io.github.ir0nbyte.pifdetector

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger

/**
 * An isolated service forked from this app's own app zygote. It answers one
 * request with the mount reasons its own mount table produces, and that is
 * all it does: an isolated process has no Context worth the name, no package
 * manager and no binder services, so the native call it makes touches none.
 *
 * It never throws. Any failure answers with an empty array and [KEY_FAILED]
 * set, which the caller reads as "could not observe" and never as a finding.
 * The reply is a handful of ints, well under any binder limit.
 */
class AppZygoteService : Service() {

    private val messenger = Messenger(Handler(Looper.getMainLooper()) { msg ->
        try {
            val reply = Message.obtain(null, MSG_REPLY)
            reply.data = answer()
            msg.replyTo?.send(reply)
        } catch (_: Throwable) {
        }
        true
    })

    override fun onBind(intent: Intent?): IBinder = messenger.binder

    companion object {
        const val MSG_REQUEST = 1
        const val MSG_REPLY = 2
        const val KEY_CODES = "codes"
        const val KEY_FAILED = "failed"

        private val libraryLoaded: Boolean = try {
            System.loadLibrary("pifdetector")
            true
        } catch (_: Throwable) {
            false
        }

        private fun answer(): Bundle {
            val codes: IntArray? = try {
                if (libraryLoaded) AppZygoteMounts.nativeMountReasons() else null
            } catch (_: Throwable) {
                null
            }
            return Bundle().apply {
                putIntArray(KEY_CODES, codes ?: IntArray(0))
                putBoolean(KEY_FAILED, codes == null)
            }
        }
    }
}
