// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EC_KEY_METHOD_get_sign$psign {

    int apply(int x0, jdk.incubator.foreign.MemoryAddress x1, int x2, jdk.incubator.foreign.MemoryAddress x3, jdk.incubator.foreign.MemoryAddress x4, jdk.incubator.foreign.MemoryAddress x5, jdk.incubator.foreign.MemoryAddress x6, jdk.incubator.foreign.MemoryAddress x7);
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_get_sign$psign fi) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_get_sign$psign.class, fi, constants$418.EC_KEY_METHOD_get_sign$psign$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EC_KEY_METHOD_get_sign$psign fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EC_KEY_METHOD_get_sign$psign.class, fi, constants$418.EC_KEY_METHOD_get_sign$psign$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EC_KEY_METHOD_get_sign$psign ofAddress(MemoryAddress addr) {
        return (int x0, jdk.incubator.foreign.MemoryAddress x1, int x2, jdk.incubator.foreign.MemoryAddress x3, jdk.incubator.foreign.MemoryAddress x4, jdk.incubator.foreign.MemoryAddress x5, jdk.incubator.foreign.MemoryAddress x6, jdk.incubator.foreign.MemoryAddress x7) -> {
            try {
                return (int)constants$418.EC_KEY_METHOD_get_sign$psign$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4, x5, x6, x7);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

