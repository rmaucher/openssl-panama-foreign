// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface ASN1_SCTX_new$scan_cb {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(ASN1_SCTX_new$scan_cb fi) {
        return RuntimeHelper.upcallStub(ASN1_SCTX_new$scan_cb.class, fi, constants$249.ASN1_SCTX_new$scan_cb$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(ASN1_SCTX_new$scan_cb fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(ASN1_SCTX_new$scan_cb.class, fi, constants$249.ASN1_SCTX_new$scan_cb$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static ASN1_SCTX_new$scan_cb ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$250.ASN1_SCTX_new$scan_cb$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


