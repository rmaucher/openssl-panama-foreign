// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface sk_ASN1_STRING_TABLE_freefunc {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(sk_ASN1_STRING_TABLE_freefunc fi) {
        return RuntimeHelper.upcallStub(sk_ASN1_STRING_TABLE_freefunc.class, fi, constants$179.sk_ASN1_STRING_TABLE_freefunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(sk_ASN1_STRING_TABLE_freefunc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(sk_ASN1_STRING_TABLE_freefunc.class, fi, constants$179.sk_ASN1_STRING_TABLE_freefunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static sk_ASN1_STRING_TABLE_freefunc ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$179.sk_ASN1_STRING_TABLE_freefunc$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


