// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_TRUST_set_default$trust {

    int apply(int x0, jdk.incubator.foreign.MemoryAddress x1, int x2);
    static CLinker.UpcallStub allocate(X509_TRUST_set_default$trust fi) {
        return RuntimeHelper.upcallStub(X509_TRUST_set_default$trust.class, fi, constants$658.X509_TRUST_set_default$trust$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;I)I");
    }
    static CLinker.UpcallStub allocate(X509_TRUST_set_default$trust fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_TRUST_set_default$trust.class, fi, constants$658.X509_TRUST_set_default$trust$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;I)I", scope);
    }
    static X509_TRUST_set_default$trust ofAddress(MemoryAddress addr) {
        return (int x0, jdk.incubator.foreign.MemoryAddress x1, int x2) -> {
            try {
                return (int)constants$658.X509_TRUST_set_default$trust$MH.invokeExact((Addressable)addr, x0, x1, x2);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


