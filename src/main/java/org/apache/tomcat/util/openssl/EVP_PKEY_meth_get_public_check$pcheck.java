// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_PKEY_meth_get_public_check$pcheck {

    int apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(EVP_PKEY_meth_get_public_check$pcheck fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_PKEY_meth_get_public_check$pcheck.class, fi, constants$381.EVP_PKEY_meth_get_public_check$pcheck$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_PKEY_meth_get_public_check$pcheck ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("EVP_PKEY_meth_get_public_check$pcheck::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (int)constants$381.EVP_PKEY_meth_get_public_check$pcheck$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


