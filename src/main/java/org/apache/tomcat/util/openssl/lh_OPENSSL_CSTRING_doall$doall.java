// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface lh_OPENSSL_CSTRING_doall$doall {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(lh_OPENSSL_CSTRING_doall$doall fi) {
        return RuntimeHelper.upcallStub(lh_OPENSSL_CSTRING_doall$doall.class, fi, constants$536.lh_OPENSSL_CSTRING_doall$doall$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(lh_OPENSSL_CSTRING_doall$doall fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(lh_OPENSSL_CSTRING_doall$doall.class, fi, constants$536.lh_OPENSSL_CSTRING_doall$doall$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static lh_OPENSSL_CSTRING_doall$doall ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$536.lh_OPENSSL_CSTRING_doall$doall$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


