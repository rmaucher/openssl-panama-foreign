// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface sk_OPENSSL_CSTRING_freefunc {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(sk_OPENSSL_CSTRING_freefunc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(sk_OPENSSL_CSTRING_freefunc.class, fi, constants$50.sk_OPENSSL_CSTRING_freefunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static sk_OPENSSL_CSTRING_freefunc ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("sk_OPENSSL_CSTRING_freefunc::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$50.sk_OPENSSL_CSTRING_freefunc$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


