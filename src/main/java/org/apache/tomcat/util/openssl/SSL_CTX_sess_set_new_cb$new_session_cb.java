// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface SSL_CTX_sess_set_new_cb$new_session_cb {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static CLinker.UpcallStub allocate(SSL_CTX_sess_set_new_cb$new_session_cb fi) {
        return RuntimeHelper.upcallStub(SSL_CTX_sess_set_new_cb$new_session_cb.class, fi, constants$766.SSL_CTX_sess_set_new_cb$new_session_cb$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(SSL_CTX_sess_set_new_cb$new_session_cb fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(SSL_CTX_sess_set_new_cb$new_session_cb.class, fi, constants$766.SSL_CTX_sess_set_new_cb$new_session_cb$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static SSL_CTX_sess_set_new_cb$new_session_cb ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                return (int)constants$766.SSL_CTX_sess_set_new_cb$new_session_cb$MH.invokeExact((Addressable)addr, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


