// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_set_verifyctx$verifyctx_init {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_set_verifyctx$verifyctx_init fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_set_verifyctx$verifyctx_init.class, fi, constants$361.EVP_PKEY_meth_set_verifyctx$verifyctx_init$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_set_verifyctx$verifyctx_init fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_set_verifyctx$verifyctx_init.class, fi, constants$361.EVP_PKEY_meth_set_verifyctx$verifyctx_init$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_meth_set_verifyctx$verifyctx_init ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                return (int)constants$361.EVP_PKEY_meth_set_verifyctx$verifyctx_init$MH.invokeExact((Addressable)addr, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


