// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$84 {

    static final FunctionDescriptor pthread_attr_setschedparam$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_setschedparam$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setschedparam",
        constants$84.pthread_attr_setschedparam$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_getschedpolicy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_getschedpolicy$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getschedpolicy",
        constants$84.pthread_attr_getschedpolicy$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_setschedpolicy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle pthread_attr_setschedpolicy$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setschedpolicy",
        constants$84.pthread_attr_setschedpolicy$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_getinheritsched$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_getinheritsched$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getinheritsched",
        constants$84.pthread_attr_getinheritsched$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_setinheritsched$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle pthread_attr_setinheritsched$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_setinheritsched",
        constants$84.pthread_attr_setinheritsched$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_getscope$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_attr_getscope$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_getscope",
        constants$84.pthread_attr_getscope$FUNC, false
    );
}


