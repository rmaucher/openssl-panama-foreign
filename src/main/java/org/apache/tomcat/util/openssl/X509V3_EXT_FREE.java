// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509V3_EXT_FREE {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(X509V3_EXT_FREE fi) {
        return RuntimeHelper.upcallStub(X509V3_EXT_FREE.class, fi, constants$928.X509V3_EXT_FREE$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(X509V3_EXT_FREE fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509V3_EXT_FREE.class, fi, constants$928.X509V3_EXT_FREE$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static X509V3_EXT_FREE ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$928.X509V3_EXT_FREE$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

