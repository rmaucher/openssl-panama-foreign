// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EC_KEY_METHOD_set_init$finish {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_set_init$finish fi) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_set_init$finish.class, fi, constants$410.EC_KEY_METHOD_set_init$finish$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_set_init$finish fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_set_init$finish.class, fi, constants$410.EC_KEY_METHOD_set_init$finish$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static EC_KEY_METHOD_set_init$finish ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$410.EC_KEY_METHOD_set_init$finish$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


