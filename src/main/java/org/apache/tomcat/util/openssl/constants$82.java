// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$82 {

    static final FunctionDescriptor pthread_exit$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle pthread_exit$MH = RuntimeHelper.downcallHandle(
        "pthread_exit",
        constants$82.pthread_exit$FUNC, false
    );
    static final FunctionDescriptor pthread_join$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle pthread_join$MH = RuntimeHelper.downcallHandle(
        "pthread_join",
        constants$82.pthread_join$FUNC, false
    );
    static final FunctionDescriptor pthread_detach$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG
    );
    static final MethodHandle pthread_detach$MH = RuntimeHelper.downcallHandle(
        "pthread_detach",
        constants$82.pthread_detach$FUNC, false
    );
    static final FunctionDescriptor pthread_self$FUNC = FunctionDescriptor.of(JAVA_LONG);
    static final MethodHandle pthread_self$MH = RuntimeHelper.downcallHandle(
        "pthread_self",
        constants$82.pthread_self$FUNC, false
    );
    static final FunctionDescriptor pthread_equal$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle pthread_equal$MH = RuntimeHelper.downcallHandle(
        "pthread_equal",
        constants$82.pthread_equal$FUNC, false
    );
    static final FunctionDescriptor pthread_attr_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_attr_init$MH = RuntimeHelper.downcallHandle(
        "pthread_attr_init",
        constants$82.pthread_attr_init$FUNC, false
    );
}


