// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface BIO_meth_set_destroy$destroy {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(BIO_meth_set_destroy$destroy fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(BIO_meth_set_destroy$destroy.class, fi, constants$142.BIO_meth_set_destroy$destroy$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static BIO_meth_set_destroy$destroy ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("BIO_meth_set_destroy$destroy::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$142.BIO_meth_set_destroy$destroy$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


