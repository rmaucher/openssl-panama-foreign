// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface sk_POLICYINFO_freefunc {

    void apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(sk_POLICYINFO_freefunc fi) {
        return RuntimeHelper.upcallStub(sk_POLICYINFO_freefunc.class, fi, constants$966.sk_POLICYINFO_freefunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V");
    }
    static CLinker.UpcallStub allocate(sk_POLICYINFO_freefunc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(sk_POLICYINFO_freefunc.class, fi, constants$966.sk_POLICYINFO_freefunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)V", scope);
    }
    static sk_POLICYINFO_freefunc ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                constants$966.sk_POLICYINFO_freefunc$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


