// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface ENGINE_PKEY_METHS_PTR {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, int x3);
    static CLinker.UpcallStub allocate(ENGINE_PKEY_METHS_PTR fi) {
        return RuntimeHelper.upcallStub(ENGINE_PKEY_METHS_PTR.class, fi, constants$1094.ENGINE_PKEY_METHS_PTR$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;I)I");
    }
    static CLinker.UpcallStub allocate(ENGINE_PKEY_METHS_PTR fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(ENGINE_PKEY_METHS_PTR.class, fi, constants$1094.ENGINE_PKEY_METHS_PTR$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;I)I", scope);
    }
    static ENGINE_PKEY_METHS_PTR ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, int x3) -> {
            try {
                return (int)constants$1094.ENGINE_PKEY_METHS_PTR$MH.invokeExact((Addressable)addr, x0, x1, x2, x3);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


