// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_CRL_METHOD_new$crl_free {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(X509_CRL_METHOD_new$crl_free fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_CRL_METHOD_new$crl_free.class, fi, constants$623.X509_CRL_METHOD_new$crl_free$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static X509_CRL_METHOD_new$crl_free ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("X509_CRL_METHOD_new$crl_free::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$624.X509_CRL_METHOD_new$crl_free$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


