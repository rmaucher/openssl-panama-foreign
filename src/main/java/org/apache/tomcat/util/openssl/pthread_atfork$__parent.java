// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface pthread_atfork$__parent {

    void apply();
    static CLinker.UpcallStub allocate(pthread_atfork$__parent fi) {
        return RuntimeHelper.upcallStub(pthread_atfork$__parent.class, fi, constants$100.pthread_atfork$__parent$FUNC, "()V");
    }
    static CLinker.UpcallStub allocate(pthread_atfork$__parent fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(pthread_atfork$__parent.class, fi, constants$100.pthread_atfork$__parent$FUNC, "()V", scope);
    }
    static pthread_atfork$__parent ofAddress(MemoryAddress addr) {
        return () -> {
            try {
                constants$100.pthread_atfork$__parent$MH.invokeExact((Addressable)addr);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


