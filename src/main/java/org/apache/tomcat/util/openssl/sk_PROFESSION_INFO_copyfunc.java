// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface sk_PROFESSION_INFO_copyfunc {

    jdk.incubator.foreign.MemoryAddress apply(jdk.incubator.foreign.MemoryAddress x0);
    static NativeSymbol allocate(sk_PROFESSION_INFO_copyfunc fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(sk_PROFESSION_INFO_copyfunc.class, fi, constants$1064.sk_PROFESSION_INFO_copyfunc$FUNC, "(Ljdk/incubator/foreign/MemoryAddress;)Ljdk/incubator/foreign/MemoryAddress;", scope);
    }
    static sk_PROFESSION_INFO_copyfunc ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("sk_PROFESSION_INFO_copyfunc::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return (jdk.incubator.foreign.MemoryAddress x0) -> {
            try {
                return (jdk.incubator.foreign.MemoryAddress)constants$1064.sk_PROFESSION_INFO_copyfunc$MH.invokeExact(symbol, x0);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


