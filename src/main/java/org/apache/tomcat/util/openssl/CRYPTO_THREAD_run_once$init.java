// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface CRYPTO_THREAD_run_once$init {

    void apply();
    static CLinker.UpcallStub allocate(CRYPTO_THREAD_run_once$init fi) {
        return RuntimeHelper.upcallStub(CRYPTO_THREAD_run_once$init.class, fi, constants$100.CRYPTO_THREAD_run_once$init$FUNC, "()V");
    }
    static CLinker.UpcallStub allocate(CRYPTO_THREAD_run_once$init fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(CRYPTO_THREAD_run_once$init.class, fi, constants$100.CRYPTO_THREAD_run_once$init$FUNC, "()V", scope);
    }
    static CRYPTO_THREAD_run_once$init ofAddress(MemoryAddress addr) {
        return () -> {
            try {
                constants$101.CRYPTO_THREAD_run_once$init$MH.invokeExact((Addressable)addr);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


