// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_set_encrypt$encrypt_init {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_set_encrypt$encrypt_init fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_set_encrypt$encrypt_init.class, fi, constants$362.EVP_PKEY_meth_set_encrypt$encrypt_init$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_set_encrypt$encrypt_init fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_set_encrypt$encrypt_init.class, fi, constants$362.EVP_PKEY_meth_set_encrypt$encrypt_init$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_meth_set_encrypt$encrypt_init ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$362.EVP_PKEY_meth_set_encrypt$encrypt_init$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


