// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface CRYPTO_get_mem_functions$m {

    jdk.incubator.foreign.MemoryAddress apply(long x0, jdk.incubator.foreign.MemoryAddress x1, int x2);
    static CLinker.UpcallStub allocate(CRYPTO_get_mem_functions$m fi) {
        return RuntimeHelper.upcallStub(CRYPTO_get_mem_functions$m.class, fi, constants$71.CRYPTO_get_mem_functions$m$FUNC, "(JLjdk/incubator/foreign/MemoryAddress;I)Ljdk/incubator/foreign/MemoryAddress;");
    }
    static CLinker.UpcallStub allocate(CRYPTO_get_mem_functions$m fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(CRYPTO_get_mem_functions$m.class, fi, constants$71.CRYPTO_get_mem_functions$m$FUNC, "(JLjdk/incubator/foreign/MemoryAddress;I)Ljdk/incubator/foreign/MemoryAddress;", scope);
    }
    static CRYPTO_get_mem_functions$m ofAddress(MemoryAddress addr) {
        return (long x0, jdk.incubator.foreign.MemoryAddress x1, int x2) -> {
            try {
                return (jdk.incubator.foreign.MemoryAddress)constants$71.CRYPTO_get_mem_functions$m$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


