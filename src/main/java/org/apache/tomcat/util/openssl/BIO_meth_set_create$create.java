// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface BIO_meth_set_create$create {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(BIO_meth_set_create$create fi) {
        return RuntimeHelper.upcallStub(BIO_meth_set_create$create.class, fi, constants$141.BIO_meth_set_create$create$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(BIO_meth_set_create$create fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(BIO_meth_set_create$create.class, fi, constants$141.BIO_meth_set_create$create$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static BIO_meth_set_create$create ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$141.BIO_meth_set_create$create$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


