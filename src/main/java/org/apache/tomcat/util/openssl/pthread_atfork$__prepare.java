// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public interface pthread_atfork$__prepare {

    void apply();
    static CLinker.UpcallStub allocate(pthread_atfork$__prepare fi) {
        return RuntimeHelper.upcallStub(pthread_atfork$__prepare.class, fi, constants$99.pthread_atfork$__prepare$FUNC, "()V");
    }
    static CLinker.UpcallStub allocate(pthread_atfork$__prepare fi, ResourceScope scope) {
        return RuntimeHelper.upcallStub(pthread_atfork$__prepare.class, fi, constants$99.pthread_atfork$__prepare$FUNC, "()V", scope);
    }
    static pthread_atfork$__prepare ofAddress(MemoryAddress addr) {
        return () -> {
            try {
                constants$99.pthread_atfork$__prepare$MH.invokeExact((Addressable)addr);
            } catch (Throwable ex$) {
                throw new AssertionError("should not reach here", ex$);
            }
        };
    }
}


