// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_STORE_CTX_cert_crl_fn {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2);
    static CLinker.UpcallStub allocate(X509_STORE_CTX_cert_crl_fn fi) {
        return RuntimeHelper.upcallStub(X509_STORE_CTX_cert_crl_fn.class, fi, constants$554.X509_STORE_CTX_cert_crl_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(X509_STORE_CTX_cert_crl_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_STORE_CTX_cert_crl_fn.class, fi, constants$554.X509_STORE_CTX_cert_crl_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static X509_STORE_CTX_cert_crl_fn ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2) -> {
            try {
                return (int)constants$554.X509_STORE_CTX_cert_crl_fn$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


