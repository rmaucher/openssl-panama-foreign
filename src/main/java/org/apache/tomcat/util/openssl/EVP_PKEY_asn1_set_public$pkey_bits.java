// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_asn1_set_public$pkey_bits {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(EVP_PKEY_asn1_set_public$pkey_bits fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_asn1_set_public$pkey_bits.class, fi, constants$335.EVP_PKEY_asn1_set_public$pkey_bits$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_asn1_set_public$pkey_bits fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_asn1_set_public$pkey_bits.class, fi, constants$335.EVP_PKEY_asn1_set_public$pkey_bits$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_asn1_set_public$pkey_bits ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$335.EVP_PKEY_asn1_set_public$pkey_bits$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

