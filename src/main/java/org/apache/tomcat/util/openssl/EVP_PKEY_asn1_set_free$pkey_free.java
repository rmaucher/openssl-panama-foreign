// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_asn1_set_free$pkey_free {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(EVP_PKEY_asn1_set_free$pkey_free fi) {
        return RuntimeHelper.upcallStub(EVP_PKEY_asn1_set_free$pkey_free.class, fi, constants$339.EVP_PKEY_asn1_set_free$pkey_free$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(EVP_PKEY_asn1_set_free$pkey_free fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_asn1_set_free$pkey_free.class, fi, constants$339.EVP_PKEY_asn1_set_free$pkey_free$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static EVP_PKEY_asn1_set_free$pkey_free ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$339.EVP_PKEY_asn1_set_free$pkey_free$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


