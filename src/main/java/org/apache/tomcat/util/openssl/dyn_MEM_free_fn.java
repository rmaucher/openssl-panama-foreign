// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface dyn_MEM_free_fn {

    void apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, int x2);
    static CLinker.UpcallStub allocate(dyn_MEM_free_fn fi) {
        return RuntimeHelper.upcallStub(dyn_MEM_free_fn.class, fi, constants$1116.dyn_MEM_free_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;I)V");
    }
    static CLinker.UpcallStub allocate(dyn_MEM_free_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(dyn_MEM_free_fn.class, fi, constants$1116.dyn_MEM_free_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;I)V", scope);
    }
    static dyn_MEM_free_fn ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, int x2) -> {
            try {
                constants$1116.dyn_MEM_free_fn$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


