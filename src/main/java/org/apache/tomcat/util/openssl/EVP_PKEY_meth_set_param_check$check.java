// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_set_param_check$check {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_set_param_check$check fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_set_param_check$check.class, fi, constants$367.EVP_PKEY_meth_set_param_check$check$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_set_param_check$check fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_set_param_check$check.class, fi, constants$367.EVP_PKEY_meth_set_param_check$check$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_meth_set_param_check$check ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$368.EVP_PKEY_meth_set_param_check$check$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

