package io.github.ir0nbyte.pifdetector

/**
 * The native mount classification on its own, for [AppZygoteService].
 *
 * It sits on a class of its own so an isolated process can call it without
 * constructing [DetectionRunner], whose constructor wants a main looper and
 * whose other entry points want a Context. JNI_OnLoad registers this method
 * together with DetectionRunner's, all or nothing.
 */
object AppZygoteMounts {

    /**
     * The mount reasons (901, 902, 905) this process's own mount table
     * produces under the same classifier the main engine runs, or null when
     * the engine could not allocate the answer.
     */
    @JvmStatic
    external fun nativeMountReasons(): IntArray?
}
