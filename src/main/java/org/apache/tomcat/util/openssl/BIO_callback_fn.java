// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface BIO_callback_fn {

    long apply(jdk.incubator.foreign.MemoryAddress x0, int x1, jdk.incubator.foreign.MemoryAddress x2, int x3, long x4, long x5);
    static CLinker.UpcallStub allocate(BIO_callback_fn fi) {
        return RuntimeHelper.upcallStub(BIO_callback_fn.class, fi, constants$105.BIO_callback_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;IJJ)J");
    }
    static CLinker.UpcallStub allocate(BIO_callback_fn fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(BIO_callback_fn.class, fi, constants$105.BIO_callback_fn$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;IJJ)J", scope);
    }
    static BIO_callback_fn ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, int x1, jdk.incubator.foreign.MemoryAddress x2, int x3, long x4, long x5) -> {
            try {
                return (long)constants$105.BIO_callback_fn$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4, x5);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

