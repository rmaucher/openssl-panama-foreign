// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_CIPHER_meth_set_do_cipher$do_cipher {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, long x3);
    static CLinker.UpcallStub allocate(EVP_CIPHER_meth_set_do_cipher$do_cipher fi) {
        return RuntimeHelper.upcallStub(EVP_CIPHER_meth_set_do_cipher$do_cipher.class, fi, constants$268.EVP_CIPHER_meth_set_do_cipher$do_cipher$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;J)I");
    }
    static CLinker.UpcallStub allocate(EVP_CIPHER_meth_set_do_cipher$do_cipher fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_CIPHER_meth_set_do_cipher$do_cipher.class, fi, constants$268.EVP_CIPHER_meth_set_do_cipher$do_cipher$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;J)I", scope);
    }
    static EVP_CIPHER_meth_set_do_cipher$do_cipher ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, long x3) -> {
            try {
                return (int)constants$268.EVP_CIPHER_meth_set_do_cipher$do_cipher$MH.invokeExact((Addressable)addr, x0, x1, x2, x3);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


