// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$97 {

    static final FunctionDescriptor pthread_spin_trylock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_spin_trylock$MH = RuntimeHelper.downcallHandle(
        "pthread_spin_trylock",
        constants$97.pthread_spin_trylock$FUNC, false
    );
    static final FunctionDescriptor pthread_spin_unlock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_spin_unlock$MH = RuntimeHelper.downcallHandle(
        "pthread_spin_unlock",
        constants$97.pthread_spin_unlock$FUNC, false
    );
    static final FunctionDescriptor pthread_barrier_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle pthread_barrier_init$MH = RuntimeHelper.downcallHandle(
        "pthread_barrier_init",
        constants$97.pthread_barrier_init$FUNC, false
    );
    static final FunctionDescriptor pthread_barrier_destroy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_barrier_destroy$MH = RuntimeHelper.downcallHandle(
        "pthread_barrier_destroy",
        constants$97.pthread_barrier_destroy$FUNC, false
    );
    static final FunctionDescriptor pthread_barrier_wait$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_barrier_wait$MH = RuntimeHelper.downcallHandle(
        "pthread_barrier_wait",
        constants$97.pthread_barrier_wait$FUNC, false
    );
    static final FunctionDescriptor pthread_barrierattr_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle pthread_barrierattr_init$MH = RuntimeHelper.downcallHandle(
        "pthread_barrierattr_init",
        constants$97.pthread_barrierattr_init$FUNC, false
    );
}

