// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface RSA_meth_set_pub_enc$pub_enc {

    int apply(int x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, jdk.incubator.foreign.MemoryAddress x3, int x4);
    static CLinker.UpcallStub allocate(RSA_meth_set_pub_enc$pub_enc fi) {
        return RuntimeHelper.upcallStub(RSA_meth_set_pub_enc$pub_enc.class, fi, constants$438.RSA_meth_set_pub_enc$pub_enc$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;I)I");
    }
    static CLinker.UpcallStub allocate(RSA_meth_set_pub_enc$pub_enc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(RSA_meth_set_pub_enc$pub_enc.class, fi, constants$438.RSA_meth_set_pub_enc$pub_enc$FUNC, "(ILjdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;I)I", scope);
    }
    static RSA_meth_set_pub_enc$pub_enc ofAddress(MemoryAddress addr) {
        return (int x0, jdk.incubator.foreign.MemoryAddress x1, jdk.incubator.foreign.MemoryAddress x2, jdk.incubator.foreign.MemoryAddress x3, int x4) -> {
            try {
                return (int)constants$438.RSA_meth_set_pub_enc$pub_enc$MH.invokeExact((Addressable)addr, x0, x1, x2, x3, x4);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


