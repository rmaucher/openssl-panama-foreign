// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface SSL_CTX_set_msg_callback$cb {

    void apply(int x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3, long x4, jdk.incubator.foreign.MemoryAddress x5, jdk.incubator.foreign.MemoryAddress x6);
    static NativeSymbol allocate(SSL_CTX_set_msg_callback$cb fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(SSL_CTX_set_msg_callback$cb.class, fi, constants$764.SSL_CTX_set_msg_callback$cb$FUNC, "(IIILjdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static SSL_CTX_set_msg_callback$cb ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("SSL_CTX_set_msg_callback$cb::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (int x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3, long x4, jdk.incubator.foreign.MemoryAddress x5, jdk.incubator.foreign.MemoryAddress x6) -> {
            try {
                constants$764.SSL_CTX_set_msg_callback$cb$MH.invokeExact(symbol, x0, x1, x2, x3, x4, x5, x6);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


