// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_STORE_CTX_cleanup_fn {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(X509_STORE_CTX_cleanup_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_STORE_CTX_cleanup_fn.class, fi, constants$556.X509_STORE_CTX_cleanup_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static X509_STORE_CTX_cleanup_fn ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("X509_STORE_CTX_cleanup_fn::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$556.X509_STORE_CTX_cleanup_fn$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


