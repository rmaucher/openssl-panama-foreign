// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface DH_meth_set_generate_key$generate_key {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(DH_meth_set_generate_key$generate_key fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(DH_meth_set_generate_key$generate_key.class, fi, constants$456.DH_meth_set_generate_key$generate_key$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static DH_meth_set_generate_key$generate_key ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("DH_meth_set_generate_key$generate_key::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$457.DH_meth_set_generate_key$generate_key$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


