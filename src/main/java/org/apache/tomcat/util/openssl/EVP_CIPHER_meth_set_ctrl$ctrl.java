// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_CIPHER_meth_set_ctrl$ctrl {

    int apply(jdk.incubator.foreign.MemoryAddress x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3);
    static NativeSymbol allocate(EVP_CIPHER_meth_set_ctrl$ctrl fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_CIPHER_meth_set_ctrl$ctrl.class, fi, constants$270.EVP_CIPHER_meth_set_ctrl$ctrl$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;IILjdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_CIPHER_meth_set_ctrl$ctrl ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("EVP_CIPHER_meth_set_ctrl$ctrl::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0, int x1, int x2, jdk.incubator.foreign.MemoryAddress x3) -> {
            try {
                return (int)constants$270.EVP_CIPHER_meth_set_ctrl$ctrl$MH.invokeExact(symbol, x0, x1, x2, x3);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


