package io.github.ir0nbyte.pifdetector

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Asks [AppZygoteService], forked from this app's own app zygote, which mount
 * reasons its mount table produces. Blocks for at most [TIMEOUT_MS] and so
 * must run off the main thread; on the main thread it refuses.
 *
 * Every way of not getting a clean answer is [Outcome.NotObservable], which
 * [AppZygoteCheck] reads as silence.
 */
class AppZygoteProbe {

    sealed class Outcome {
        data class Observed(val childReasons: List<Int>) : Outcome()
        data class NotObservable(val why: String) : Outcome()
    }

    fun probe(context: Context, mainReasons: List<Int>): AppZygoteCheck.Verdict {
        val outcome = observe(context)
        val child = (outcome as? Outcome.Observed)?.childReasons
        return AppZygoteCheck.evaluate(mainReasons, child)
    }

    fun observe(context: Context): Outcome {
        return try {
            observeOrThrow(context)
        } catch (t: Throwable) {
            Outcome.NotObservable("threw ${t.javaClass.simpleName}")
        }
    }

    private fun observeOrThrow(context: Context): Outcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Outcome.NotObservable("api ${Build.VERSION.SDK_INT}")
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return Outcome.NotObservable("main thread")
        }

        val replyThread = HandlerThread("pifd-appzygote").apply { start() }
        val answer = AtomicReference<Outcome?>()
        val done = CountDownLatch(1)
        val replyTo = Messenger(Handler(replyThread.looper) { msg ->
            answer.compareAndSet(null, parse(msg))
            done.countDown()
            true
        })
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service == null) return
                try {
                    val request = Message.obtain(null, AppZygoteService.MSG_REQUEST)
                    request.replyTo = replyTo
                    Messenger(service).send(request)
                } catch (t: Throwable) {
                    answer.compareAndSet(null, Outcome.NotObservable("send failed"))
                    done.countDown()
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                answer.compareAndSet(null, Outcome.NotObservable("disconnected"))
                done.countDown()
            }

            override fun onBindingDied(name: ComponentName?) {
                answer.compareAndSet(null, Outcome.NotObservable("binding died"))
                done.countDown()
            }

            override fun onNullBinding(name: ComponentName?) {
                answer.compareAndSet(null, Outcome.NotObservable("null binding"))
                done.countDown()
            }
        }

        try {
            val bound = context.bindService(
                Intent(context, AppZygoteService::class.java),
                connection,
                Context.BIND_AUTO_CREATE,
            )
            if (!bound) return Outcome.NotObservable("bind refused")
            if (!done.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                return Outcome.NotObservable("timeout")
            }
            return answer.get() ?: Outcome.NotObservable("no answer")
        } finally {
            // Unbind whatever bindService returned: a refused bind can still
            // hold a registration on some releases.
            try {
                context.unbindService(connection)
            } catch (_: Throwable) {
            }
            replyThread.quitSafely()
        }
    }

    companion object {
        const val TIMEOUT_MS = 4000L

        internal fun parse(msg: Message): Outcome {
            if (msg.what != AppZygoteService.MSG_REPLY) {
                return Outcome.NotObservable("unexpected reply ${msg.what}")
            }
            val data = msg.data ?: return Outcome.NotObservable("empty reply")
            if (!data.containsKey(AppZygoteService.KEY_FAILED) ||
                !data.containsKey(AppZygoteService.KEY_CODES)
            ) {
                return Outcome.NotObservable("malformed reply")
            }
            if (data.getBoolean(AppZygoteService.KEY_FAILED, true)) {
                return Outcome.NotObservable("child failed")
            }
            val codes = data.getIntArray(AppZygoteService.KEY_CODES)
                ?: return Outcome.NotObservable("malformed reply")
            return Outcome.Observed(codes.toList())
        }
    }
}
