// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface sk_X509_CRL_freefunc {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(sk_X509_CRL_freefunc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(sk_X509_CRL_freefunc.class, fi, constants$516.sk_X509_CRL_freefunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static sk_X509_CRL_freefunc ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("sk_X509_CRL_freefunc::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$517.sk_X509_CRL_freefunc$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


