// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$93 {

    static final FunctionDescriptor pthread_rwlock_trywrlock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_rwlock_trywrlock$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlock_trywrlock",
        constants$93.pthread_rwlock_trywrlock$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlock_timedwrlock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_rwlock_timedwrlock$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlock_timedwrlock",
        constants$93.pthread_rwlock_timedwrlock$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlock_unlock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_rwlock_unlock$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlock_unlock",
        constants$93.pthread_rwlock_unlock$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlockattr_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_rwlockattr_init$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlockattr_init",
        constants$93.pthread_rwlockattr_init$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlockattr_destroy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_rwlockattr_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlockattr_destroy",
        constants$93.pthread_rwlockattr_destroy$FUNC, false
    );
    static final FunctionDescriptor pthread_rwlockattr_getpshared$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle pthread_rwlockattr_getpshared$MH = RuntimeHelper.downcallHandle(
        "pthread_rwlockattr_getpshared",
        constants$93.pthread_rwlockattr_getpshared$FUNC, false
    );
}

