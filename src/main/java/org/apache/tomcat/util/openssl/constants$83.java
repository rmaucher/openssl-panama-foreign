// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$83 {

    static final FunctionDescriptor pthread_attr_destroy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_attr_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_destroy",
        constants$83.pthread_attr_destroy$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_getdetachstate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_getdetachstate$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getdetachstate",
        constants$83.pthread_attr_getdetachstate$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_setdetachstate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle pthread_attr_setdetachstate$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setdetachstate",
        constants$83.pthread_attr_setdetachstate$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_getguardsize$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_getguardsize$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getguardsize",
        constants$83.pthread_attr_getguardsize$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_setguardsize$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle pthread_attr_setguardsize$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setguardsize",
        constants$83.pthread_attr_setguardsize$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_getschedparam$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_getschedparam$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getschedparam",
        constants$83.pthread_attr_getschedparam$FUNC, false
    );
}

