// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_get_ctrl$pctrl_str {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2);
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_get_ctrl$pctrl_str fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_ctrl$pctrl_str.class, fi, constants$379.EVP_PKEY_meth_get_ctrl$pctrl_str$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_meth_get_ctrl$pctrl_str fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_ctrl$pctrl_str.class, fi, constants$379.EVP_PKEY_meth_get_ctrl$pctrl_str$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_meth_get_ctrl$pctrl_str ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2) -> {
            try {
                return (int)constants$379.EVP_PKEY_meth_get_ctrl$pctrl_str$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

