// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface DSA_meth_set_finish$finish {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(DSA_meth_set_finish$finish fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(DSA_meth_set_finish$finish.class, fi, constants$475.DSA_meth_set_finish$finish$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static DSA_meth_set_finish$finish ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("DSA_meth_set_finish$finish::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$475.DSA_meth_set_finish$finish$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


