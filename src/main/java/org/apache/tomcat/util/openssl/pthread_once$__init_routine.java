// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface pthread_once$__init_routine {

    void apply();
    static NativeSymbol allocate(pthread_once$__init_routine fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(pthread_once$__init_routine.class, fi, constants$86.pthread_once$__init_routine$FUNC, "()V", scope);
    }
    static pthread_once$__init_routine ofAddress(MemoryAddress addr, ResourceScope scope) {
        NativeSymbol symbol = NativeSymbol.ofAddress("pthread_once$__init_routine::" + Long.toHexString(addr.toRawLongValue()), addr, scope);return () -> {
            try {
                constants$86.pthread_once$__init_routine$MH.invokeExact(symbol);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


