// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface BIO_callback_fn_ex {

    long apply(jdk.incubator.foreign.MemoryAddress x0, int x1, jdk.incubator.foreign.MemoryAddress x2, long x3, int x4, long x5, int x6, jdk.incubator.foreign.MemoryAddress x7);
    static CLinker.UpcallStub allocate(BIO_callback_fn_ex fi) {
        return RuntimeHelper.upcallStub(BIO_callback_fn_ex.class, fi, constants$105.BIO_callback_fn_ex$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;JIJILjdk/incubator/foreign/MemoryAddress;)J");
    }
    static CLinker.UpcallStub allocate(BIO_callback_fn_ex fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(BIO_callback_fn_ex.class, fi, constants$105.BIO_callback_fn_ex$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;ILjdk/incubator/foreign/MemoryAddress;JIJILjdk/incubator/foreign/MemoryAddress;)J", scope);
    }
    static BIO_callback_fn_ex ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, int x1, jdk.incubator.foreign.MemoryAddress x2, long x3, int x4, long x5, int x6, jdk.incubator.foreign.MemoryAddress x7) -> {
            try {
                return (long)constants$105.BIO_callback_fn_ex$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4, x5, x6, x7);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


