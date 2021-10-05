// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface OPENSSL_LH_HASHFUNC {

    long apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(OPENSSL_LH_HASHFUNC fi) {
        return RuntimeHelper.upcallStub(OPENSSL_LH_HASHFUNC.class, fi, constants$526.OPENSSL_LH_HASHFUNC$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)J");
    }
    static CLinker.UpcallStub allocate(OPENSSL_LH_HASHFUNC fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(OPENSSL_LH_HASHFUNC.class, fi, constants$526.OPENSSL_LH_HASHFUNC$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)J", scope);
    }
    static OPENSSL_LH_HASHFUNC ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (long)constants$527.OPENSSL_LH_HASHFUNC$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

