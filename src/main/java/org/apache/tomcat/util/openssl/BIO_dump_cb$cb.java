// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface BIO_dump_cb$cb {

    int apply(jdk.incubator.foreign.MemoryAddress x0, long x1, jdk.incubator.foreign.MemoryAddress x2);
    static CLinker.UpcallStub allocate(BIO_dump_cb$cb fi) {
        return RuntimeHelper.upcallStub(BIO_dump_cb$cb.class, fi, constants$126.BIO_dump_cb$cb$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(BIO_dump_cb$cb fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(BIO_dump_cb$cb.class, fi, constants$126.BIO_dump_cb$cb$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;JLjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static BIO_dump_cb$cb ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, long x1, jdk.incubator.foreign.MemoryAddress x2) -> {
            try {
                return (int)constants$126.BIO_dump_cb$cb$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


