// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface sk_SSL_CIPHER_copyfunc {

    jdk.incubator.foreign.MemoryAddress apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(sk_SSL_CIPHER_copyfunc fi) {
        return RuntimeHelper.upcallStub(sk_SSL_CIPHER_copyfunc.class, fi, constants$783.sk_SSL_CIPHER_copyfunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)Ljdk/incubator/foreign/MemoryAddress;");
    }
    static CLinker.UpcallStub allocate(sk_SSL_CIPHER_copyfunc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(sk_SSL_CIPHER_copyfunc.class, fi, constants$783.sk_SSL_CIPHER_copyfunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)Ljdk/incubator/foreign/MemoryAddress;", scope);
    }
    static sk_SSL_CIPHER_copyfunc ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (jdk.incubator.foreign.MemoryAddress)constants$784.sk_SSL_CIPHER_copyfunc$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


