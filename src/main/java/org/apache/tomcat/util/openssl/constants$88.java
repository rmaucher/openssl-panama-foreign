// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$88 {

    static final FunctionDescriptor __pthread_unregister_cancel$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle __pthread_unregister_cancel$MH = RuntimeHelper.downcallHandle(
        "__pthread_unregister_cancel",
        constants$88.__pthread_unregister_cancel$FUNC, false
    );
    static final FunctionDescriptor __pthread_unwind_next$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle __pthread_unwind_next$MH = RuntimeHelper.downcallHandle(
        "__pthread_unwind_next",
        constants$88.__pthread_unwind_next$FUNC, false
    );
    static final FunctionDescriptor __sigsetjmp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle __sigsetjmp$MH = RuntimeHelper.downcallHandle(
        "__sigsetjmp",
        constants$88.__sigsetjmp$FUNC, false
    );
    static final FunctionDescriptor pthread_mutex_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_mutex_init$MH = RuntimeHelper.downcallHandle(
        "pthread_mutex_init",
        constants$88.pthread_mutex_init$FUNC, false
    );
    static final FunctionDescriptor pthread_mutex_destroy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_mutex_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_mutex_destroy",
        constants$88.pthread_mutex_destroy$FUNC, false
    );
    static final FunctionDescriptor pthread_mutex_trylock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_mutex_trylock$MH = RuntimeHelper.downcallHandle(
        "pthread_mutex_trylock",
        constants$88.pthread_mutex_trylock$FUNC, false
    );
}

