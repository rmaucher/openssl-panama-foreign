// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1 {

    static final FunctionDescriptor __ctype_get_mb_cur_max$FUNC = FunctionDescriptor.of(JAVA_LONG);
    static final MethodHandle __ctype_get_mb_cur_max$MH = RuntimeHelper.downcallHandle(
        "__ctype_get_mb_cur_max",
        constants$1.__ctype_get_mb_cur_max$FUNC, false
    );
    static final FunctionDescriptor atof$FUNC = FunctionDescriptor.of(JAVA_DOUBLE,
        ADDRESS
    );
    static final MethodHandle atof$MH = RuntimeHelper.downcallHandle(
        "atof",
        constants$1.atof$FUNC, false
    );
    static final FunctionDescriptor atoi$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle atoi$MH = RuntimeHelper.downcallHandle(
        "atoi",
        constants$1.atoi$FUNC, false
    );
    static final FunctionDescriptor atol$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle atol$MH = RuntimeHelper.downcallHandle(
        "atol",
        constants$1.atol$FUNC, false
    );
    static final FunctionDescriptor atoll$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle atoll$MH = RuntimeHelper.downcallHandle(
        "atoll",
        constants$1.atoll$FUNC, false
    );
    static final FunctionDescriptor strtod$FUNC = FunctionDescriptor.of(JAVA_DOUBLE,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle strtod$MH = RuntimeHelper.downcallHandle(
        "strtod",
        constants$1.strtod$FUNC, false
    );
}

