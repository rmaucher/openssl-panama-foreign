// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface SSL_CTX_keylog_cb_func {

    void apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static CLinker.UpcallStub allocate(SSL_CTX_keylog_cb_func fi) {
        return RuntimeHelper.upcallStub(SSL_CTX_keylog_cb_func.class, fi, constants$778.SSL_CTX_keylog_cb_func$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(SSL_CTX_keylog_cb_func fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(SSL_CTX_keylog_cb_func.class, fi, constants$778.SSL_CTX_keylog_cb_func$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static SSL_CTX_keylog_cb_func ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                constants$778.SSL_CTX_keylog_cb_func$MH.invokeExact((Addressable)addr, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


