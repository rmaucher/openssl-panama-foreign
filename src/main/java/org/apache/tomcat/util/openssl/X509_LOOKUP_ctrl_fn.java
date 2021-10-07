// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_LOOKUP_ctrl_fn {

    int apply(jdk.incubator.foreign.MemoryAddress x0, int x1, jdk.incubator.foreign.MemoryAddress x2, long x3, jdk.incubator.foreign.MemoryAddress x4);
    static NativeSymbol allocate(X509_LOOKUP_ctrl_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_LOOKUP_ctrl_fn.class, fi, constants$569.X509_LOOKUP_ctrl_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static X509_LOOKUP_ctrl_fn ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("X509_LOOKUP_ctrl_fn::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0, int x1, jdk.incubator.foreign.MemoryAddress x2, long x3, jdk.incubator.foreign.MemoryAddress x4) -> {
            try {
                return (int)constants$569.X509_LOOKUP_ctrl_fn$MH.invokeExact(symbol, x0, x1, x2, x3, x4);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


