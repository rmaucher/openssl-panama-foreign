// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_asn1_set_public$pub_encode {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static CLinker.UpcallStub allocate(EVP_PKEY_asn1_set_public$pub_encode fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_asn1_set_public$pub_encode.class, fi, constants$334.EVP_PKEY_asn1_set_public$pub_encode$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_asn1_set_public$pub_encode fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_asn1_set_public$pub_encode.class, fi, constants$334.EVP_PKEY_asn1_set_public$pub_encode$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_asn1_set_public$pub_encode ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                return (int)constants$334.EVP_PKEY_asn1_set_public$pub_encode$MH.invokeExact((Addressable)addr, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


