// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$94 {

    static final FunctionDescriptor pthread_rwlockattr_setpshared$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle pthread_rwlockattr_setpshared$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlockattr_setpshared",
        constants$94.pthread_rwlockattr_setpshared$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlockattr_getkind_np$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_rwlockattr_getkind_np$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlockattr_getkind_np",
        constants$94.pthread_rwlockattr_getkind_np$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlockattr_setkind_np$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle pthread_rwlockattr_setkind_np$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlockattr_setkind_np",
        constants$94.pthread_rwlockattr_setkind_np$FUNC, false
    );
    static final FunctionDescriptor pthread_cond_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_cond_init$MH = RuntimeHelper.downcallHandle(
        "pthread_cond_init",
        constants$94.pthread_cond_init$FUNC, false
    );
    static final FunctionDescriptor pthread_cond_destroy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_cond_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_cond_destroy",
        constants$94.pthread_cond_destroy$FUNC, false
    );
    static final FunctionDescriptor pthread_cond_signal$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_cond_signal$MH = RuntimeHelper.downcallHandle(
        "pthread_cond_signal",
        constants$94.pthread_cond_signal$FUNC, false
    );
}

