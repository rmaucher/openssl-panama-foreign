// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_get_encrypt$pencryptfn {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, jdk.incubator.foreign.MemoryAddress x3, long x4);
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_get_encrypt$pencryptfn fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_encrypt$pencryptfn.class, fi, constants$376.EVP_PKEY_meth_get_encrypt$pencryptfn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;J)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_get_encrypt$pencryptfn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_encrypt$pencryptfn.class, fi, constants$376.EVP_PKEY_meth_get_encrypt$pencryptfn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;J)I", scope);
    }
    static EVP_PKEY_meth_get_encrypt$pencryptfn ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, jdk.incubator.foreign.MemoryAddress x3, long x4) -> {
            try {
                return (int)constants$376.EVP_PKEY_meth_get_encrypt$pencryptfn$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


