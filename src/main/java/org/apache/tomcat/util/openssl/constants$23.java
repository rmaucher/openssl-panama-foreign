// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$23 {

    static final FunctionDescriptor nanosleep$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle nanosleep$MH = RuntimeHelper.downcallHandle(
        "nanosleep",
        constants$23.nanosleep$FUNC, false
    );
    static final FunctionDescriptor clock_getres$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle clock_getres$MH = RuntimeHelper.downcallHandle(
        "clock_getres",
        constants$23.clock_getres$FUNC, false
    );
    static final FunctionDescriptor clock_gettime$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle clock_gettime$MH = RuntimeHelper.downcallHandle(
        "clock_gettime",
        constants$23.clock_gettime$FUNC, false
    );
    static final FunctionDescriptor clock_settime$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle clock_settime$MH = RuntimeHelper.downcallHandle(
        "clock_settime",
        constants$23.clock_settime$FUNC, false
    );
    static final FunctionDescriptor clock_nanosleep$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle clock_nanosleep$MH = RuntimeHelper.downcallHandle(
        "clock_nanosleep",
        constants$23.clock_nanosleep$FUNC, false
    );
    static final FunctionDescriptor clock_getcpuclockid$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle clock_getcpuclockid$MH = RuntimeHelper.downcallHandle(
        "clock_getcpuclockid",
        constants$23.clock_getcpuclockid$FUNC, false
    );
}

