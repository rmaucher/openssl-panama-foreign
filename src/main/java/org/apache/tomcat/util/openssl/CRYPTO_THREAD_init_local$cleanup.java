// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface CRYPTO_THREAD_init_local$cleanup {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(CRYPTO_THREAD_init_local$cleanup fi) {
        return RuntimeHelper.upcallStub(CRYPTO_THREAD_init_local$cleanup.class, fi, constants$101.CRYPTO_THREAD_init_local$cleanup$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(CRYPTO_THREAD_init_local$cleanup fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(CRYPTO_THREAD_init_local$cleanup.class, fi, constants$101.CRYPTO_THREAD_init_local$cleanup$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static CRYPTO_THREAD_init_local$cleanup ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$101.CRYPTO_THREAD_init_local$cleanup$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


