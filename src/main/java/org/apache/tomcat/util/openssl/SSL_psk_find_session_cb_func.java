// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface SSL_psk_find_session_cb_func {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, long x2, jdk.incubator.foreign.MemoryAddress x3);
    static CLinker.UpcallStub allocate(SSL_psk_find_session_cb_func fi) {
        return RuntimeHelper.upcallStub(SSL_psk_find_session_cb_func.class, fi, constants$776.SSL_psk_find_session_cb_func$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(SSL_psk_find_session_cb_func fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(SSL_psk_find_session_cb_func.class, fi, constants$776.SSL_psk_find_session_cb_func$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static SSL_psk_find_session_cb_func ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, long x2, jdk.incubator.foreign.MemoryAddress x3) -> {
            try {
                return (int)constants$776.SSL_psk_find_session_cb_func$MH.invokeExact((Addressable)addr, x0, x1, x2, x3);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

