// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters {

    int apply(jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1);
    static NativeSymbol allocate(EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters.class, fi, constants$269.EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;Ljdk/incubator/foreign/MemoryAddress;)I", scope);
    }
    static EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0, jdk.incubator.foreign.MemoryAddress x1) -> {
            try {
                return (int)constants$269.EVP_CIPHER_meth_set_set_asn1_params$set_asn1_parameters$MH.invokeExact(symbol, x0, x1);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


