// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$16 {

    static final FunctionDescriptor labs$FUNC = FunctionDescriptor.of(JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle labs$MH = RuntimeHelper.downcallHandle(
        "labs",
        constants$16.labs$FUNC, false
    );
    static final FunctionDescriptor llabs$FUNC = FunctionDescriptor.of(JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle llabs$MH = RuntimeHelper.downcallHandle(
        "llabs",
        constants$16.llabs$FUNC, false
    );
    static final FunctionDescriptor div$FUNC = FunctionDescriptor.of(MemoryLayout.structLayout(
        JAVA_INT.withName("quot"),
        JAVA_INT.withName("rem")
    ),
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle div$MH = RuntimeHelper.downcallHandle(
        "div",
        constants$16.div$FUNC, false
    );
    static final FunctionDescriptor ldiv$FUNC = FunctionDescriptor.of(MemoryLayout.structLayout(
        JAVA_LONG.withName("quot"),
        JAVA_LONG.withName("rem")
    ),
        JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle ldiv$MH = RuntimeHelper.downcallHandle(
        "ldiv",
        constants$16.ldiv$FUNC, false
    );
    static final FunctionDescriptor lldiv$FUNC = FunctionDescriptor.of(MemoryLayout.structLayout(
        JAVA_LONG.withName("quot"),
        JAVA_LONG.withName("rem")
    ),
        JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle lldiv$MH = RuntimeHelper.downcallHandle(
        "lldiv",
        constants$16.lldiv$FUNC, false
    );
    static final FunctionDescriptor ecvt$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_DOUBLE,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ecvt$MH = RuntimeHelper.downcallHandle(
        "ecvt",
        constants$16.ecvt$FUNC, false
    );
}


