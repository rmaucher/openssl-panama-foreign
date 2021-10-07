// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface dyn_MEM_realloc_fn {

    jdk.incubator.foreign.MemoryAddress apply(jdk.incubator.foreign.MemoryAddress x0, long x1, jdk.incubator.foreign.MemoryAddress x2, int x3);
    static NativeSymbol allocate(dyn_MEM_realloc_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(dyn_MEM_realloc_fn.class, fi, constants$1115.dyn_MEM_realloc_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;I)Ljdk/incubator/foreign/MemoryAddress;", scope);
    }
    static dyn_MEM_realloc_fn ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("dyn_MEM_realloc_fn::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0, long x1, jdk.incubator.foreign.MemoryAddress x2, int x3) -> {
            try {
                return (jdk.incubator.foreign.MemoryAddress)constants$1115.dyn_MEM_realloc_fn$MH.invokeExact(symbol, x0, x1, x2, x3);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


