// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EC_KEY_METHOD_get_init$pset_private {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_get_init$pset_private fi) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_get_init$pset_private.class, fi, constants$416.EC_KEY_METHOD_get_init$pset_private$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_get_init$pset_private fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_get_init$pset_private.class, fi, constants$416.EC_KEY_METHOD_get_init$pset_private$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EC_KEY_METHOD_get_init$pset_private ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                return (int)constants$416.EC_KEY_METHOD_get_init$pset_private$MH.invokeExact((Addressable)addr, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


