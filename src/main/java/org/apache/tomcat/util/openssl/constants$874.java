// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$874 {

    static final FunctionDescriptor ERR_get_error$FUNC = FunctionDescriptor.of(JAVA_LONG);
    static final MethodHandle ERR_get_error$MH = RuntimeHelper.downcallHandle(
        "ERR_get_error",
        constants$874.ERR_get_error$FUNC, false
    );
    static final FunctionDescriptor ERR_get_error_line$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ERR_get_error_line$MH = RuntimeHelper.downcallHandle(
        "ERR_get_error_line",
        constants$874.ERR_get_error_line$FUNC, false
    );
    static final FunctionDescriptor ERR_get_error_line_data$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ERR_get_error_line_data$MH = RuntimeHelper.downcallHandle(
        "ERR_get_error_line_data",
        constants$874.ERR_get_error_line_data$FUNC, false
    );
    static final FunctionDescriptor ERR_peek_error$FUNC = FunctionDescriptor.of(JAVA_LONG);
    static final MethodHandle ERR_peek_error$MH = RuntimeHelper.downcallHandle(
        "ERR_peek_error",
        constants$874.ERR_peek_error$FUNC, false
    );
    static final FunctionDescriptor ERR_peek_error_line$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ERR_peek_error_line$MH = RuntimeHelper.downcallHandle(
        "ERR_peek_error_line",
        constants$874.ERR_peek_error_line$FUNC, false
    );
    static final FunctionDescriptor ERR_peek_error_line_data$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ERR_peek_error_line_data$MH = RuntimeHelper.downcallHandle(
        "ERR_peek_error_line_data",
        constants$874.ERR_peek_error_line_data$FUNC, false
    );
}

