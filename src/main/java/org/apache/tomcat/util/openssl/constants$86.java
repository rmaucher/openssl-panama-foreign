// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$86 {

    static final FunctionDescriptor pthread_attr_setstack$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle pthread_attr_setstack$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setstack",
        constants$86.pthread_attr_setstack$FUNC, false
    );
    static final FunctionDescriptor pthread_setschedparam$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_setschedparam$MH = RuntimeHelper.downcallHandle(
        "pthread_setschedparam",
        constants$86.pthread_setschedparam$FUNC, false
    );
    static final FunctionDescriptor pthread_getschedparam$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_getschedparam$MH = RuntimeHelper.downcallHandle(
        "pthread_getschedparam",
        constants$86.pthread_getschedparam$FUNC, false
    );
    static final FunctionDescriptor pthread_setschedprio$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG,
        JAVA_INT
    );
    static final MethodHandle pthread_setschedprio$MH = RuntimeHelper.downcallHandle(
        "pthread_setschedprio",
        constants$86.pthread_setschedprio$FUNC, false
    );
    static final FunctionDescriptor pthread_once$__init_routine$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle pthread_once$__init_routine$MH = RuntimeHelper.downcallHandle(
        constants$86.pthread_once$__init_routine$FUNC, false
    );
}


