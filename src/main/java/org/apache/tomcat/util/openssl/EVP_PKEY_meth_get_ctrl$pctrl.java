// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_get_ctrl$pctrl {

    int apply(jdk.incubator.foreign.MemoryAddress x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3);
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_get_ctrl$pctrl fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_ctrl$pctrl.class, fi, constants$378.EVP_PKEY_meth_get_ctrl$pctrl$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;IILjdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_get_ctrl$pctrl fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_ctrl$pctrl.class, fi, constants$378.EVP_PKEY_meth_get_ctrl$pctrl$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;IILjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_meth_get_ctrl$pctrl ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3) -> {
            try {
                return (int)constants$378.EVP_PKEY_meth_get_ctrl$pctrl$MH.invokeExact((Addressable)addr, x0, x1, x2, x3);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


