// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_CRL_METHOD_new$crl_init {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(X509_CRL_METHOD_new$crl_init fi) {
        return RuntimeHelper.upcallStub(X509_CRL_METHOD_new$crl_init.class, fi, constants$623.X509_CRL_METHOD_new$crl_init$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(X509_CRL_METHOD_new$crl_init fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_CRL_METHOD_new$crl_init.class, fi, constants$623.X509_CRL_METHOD_new$crl_init$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static X509_CRL_METHOD_new$crl_init ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$623.X509_CRL_METHOD_new$crl_init$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


