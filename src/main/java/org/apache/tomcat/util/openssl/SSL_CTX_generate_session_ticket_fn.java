// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface SSL_CTX_generate_session_ticket_fn {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static CLinker.UpcallStub allocate(SSL_CTX_generate_session_ticket_fn fi) {
        return RuntimeHelper.upcallStub(SSL_CTX_generate_session_ticket_fn.class, fi, constants$868.SSL_CTX_generate_session_ticket_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(SSL_CTX_generate_session_ticket_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(SSL_CTX_generate_session_ticket_fn.class, fi, constants$868.SSL_CTX_generate_session_ticket_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static SSL_CTX_generate_session_ticket_fn ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                return (int)constants$868.SSL_CTX_generate_session_ticket_fn$MH.invokeExact((Addressable)addr, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


