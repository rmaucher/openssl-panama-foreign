// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface BN_is_prime_fasttest$callback {

    void apply(int x0, int x1, jdk.incubator.foreign.MemoryAddress x2);
    static CLinker.UpcallStub allocate(BN_is_prime_fasttest$callback fi) {
        return RuntimeHelper.upcallStub(BN_is_prime_fasttest$callback.class, fi, constants$163.BN_is_prime_fasttest$callback$FUNC, "(IILjdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(BN_is_prime_fasttest$callback fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(BN_is_prime_fasttest$callback.class, fi, constants$163.BN_is_prime_fasttest$callback$FUNC, "(IILjdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static BN_is_prime_fasttest$callback ofAddress(MemoryAddress addr) {
        return (int x0, int x1, jdk.incubator.foreign.MemoryAddress x2) -> {
            try {
                constants$164.BN_is_prime_fasttest$callback$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

