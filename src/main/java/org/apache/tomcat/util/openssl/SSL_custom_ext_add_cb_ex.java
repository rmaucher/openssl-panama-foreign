// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface SSL_custom_ext_add_cb_ex {

    int apply(jdk.incubator.foreign.MemoryAddress x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3, jdk.incubator.foreign.MemoryAddress x4, jdk.incubator.foreign.MemoryAddress x5, long x6, jdk.incubator.foreign.MemoryAddress x7, jdk.incubator.foreign.MemoryAddress x8);
    static CLinker.UpcallStub allocate(SSL_custom_ext_add_cb_ex fi) {
        return RuntimeHelper.upcallStub(SSL_custom_ext_add_cb_ex.class, fi, constants$761.SSL_custom_ext_add_cb_ex$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;IILjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(SSL_custom_ext_add_cb_ex fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(SSL_custom_ext_add_cb_ex.class, fi, constants$761.SSL_custom_ext_add_cb_ex$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;IILjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static SSL_custom_ext_add_cb_ex ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3, jdk.incubator.foreign.MemoryAddress x4, jdk.incubator.foreign.MemoryAddress x5, long x6, jdk.incubator.foreign.MemoryAddress x7, jdk.incubator.foreign.MemoryAddress x8) -> {
            try {
                return (int)constants$762.SSL_custom_ext_add_cb_ex$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4, x5, x6, x7, x8);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


