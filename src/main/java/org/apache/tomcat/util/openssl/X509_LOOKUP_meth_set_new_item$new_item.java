// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface X509_LOOKUP_meth_set_new_item$new_item {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static CLinker.UpcallStub allocate(X509_LOOKUP_meth_set_new_item$new_item fi) {
        return RuntimeHelper.upcallStub(X509_LOOKUP_meth_set_new_item$new_item.class, fi, constants$571.X509_LOOKUP_meth_set_new_item$new_item$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I");
    }
    static CLinker.UpcallStub allocate(X509_LOOKUP_meth_set_new_item$new_item fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(X509_LOOKUP_meth_set_new_item$new_item.class, fi, constants$571.X509_LOOKUP_meth_set_new_item$new_item$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static X509_LOOKUP_meth_set_new_item$new_item ofAddress(MemoryAddress addr) {
        return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$571.X509_LOOKUP_meth_set_new_item$new_item$MH.invokeExact((Addressable)addr, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}

