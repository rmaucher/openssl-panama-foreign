// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EC_KEY_METHOD_set_verify$verify {

    int apply(int x0, jdk.incubator.foreign.MemoryAddress x1, int x2, jdk.incubator.foreign.MemoryAddress x3, int x4, jdk.incubator.foreign.MemoryAddress x5);
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_set_verify$verify fi) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_set_verify$verify.class, fi, constants$414.EC_KEY_METHOD_set_verify$verify$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_set_verify$verify fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_set_verify$verify.class, fi, constants$414.EC_KEY_METHOD_set_verify$verify$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EC_KEY_METHOD_set_verify$verify ofAddress(MemoryAddress addr) {
        return (int x0, jdk.incubator.foreign.MemoryAddress x1, int x2, jdk.incubator.foreign.MemoryAddress x3, int x4, jdk.incubator.foreign.MemoryAddress x5) -> {
            try {
                return (int)constants$414.EC_KEY_METHOD_set_verify$verify$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4, x5);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


