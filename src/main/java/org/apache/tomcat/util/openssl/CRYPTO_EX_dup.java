// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface CRYPTO_EX_dup {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, int x3, long x4, jdk.incubator.foreign.MemoryAddress x5);
    static CLinker.UpcallStub allocate(CRYPTO_EX_dup fi) {
        return RuntimeHelper.upcallStub(CRYPTO_EX_dup.class, fi, constants$68.CRYPTO_EX_dup$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;IJLjdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(CRYPTO_EX_dup fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(CRYPTO_EX_dup.class, fi, constants$68.CRYPTO_EX_dup$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;IJLjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static CRYPTO_EX_dup ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, int x3, long x4, jdk.incubator.foreign.MemoryAddress x5) -> {
            try {
                return (int)constants$68.CRYPTO_EX_dup$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4, x5);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

