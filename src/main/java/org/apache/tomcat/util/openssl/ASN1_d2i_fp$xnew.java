// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface ASN1_d2i_fp$xnew {

    jdk.incubator.foreign.MemoryAddress apply();
    static CLinker.UpcallStub allocate(ASN1_d2i_fp$xnew fi) {
        return RuntimeHelper.upcallStub(ASN1_d2i_fp$xnew.class, fi, constants$239.ASN1_d2i_fp$xnew$FUNC, "()Ljdk/incubator/foreign/MemoryAddress;");
    }
    static CLinker.UpcallStub allocate(ASN1_d2i_fp$xnew fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(ASN1_d2i_fp$xnew.class, fi, constants$239.ASN1_d2i_fp$xnew$FUNC, "()Ljdk/incubator/foreign/MemoryAddress;", scope);
    }
    static ASN1_d2i_fp$xnew ofAddress(MemoryAddress addr) {
        return () -> {
            try {
                return (jdk.incubator.foreign.MemoryAddress)constants$239.ASN1_d2i_fp$xnew$MH.invokeExact((Addressable)addr);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

