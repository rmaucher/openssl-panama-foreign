// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EC_KEY_METHOD_set_keygen$keygen {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_set_keygen$keygen fi) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_set_keygen$keygen.class, fi, constants$412.EC_KEY_METHOD_set_keygen$keygen$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_set_keygen$keygen fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_set_keygen$keygen.class, fi, constants$412.EC_KEY_METHOD_set_keygen$keygen$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EC_KEY_METHOD_set_keygen$keygen ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$412.EC_KEY_METHOD_set_keygen$keygen$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

