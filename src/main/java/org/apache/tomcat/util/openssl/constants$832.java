// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$832 {

    static final FunctionDescriptor SSL_peek$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_peek$MH = RuntimeHelper.downcallHandle(
        "SSL_peek",
        constants$832.SSL_peek$FUNC, false
    );
    static final FunctionDescriptor SSL_peek_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_peek_ex$MH = RuntimeHelper.downcallHandle(
        "SSL_peek_ex",
        constants$832.SSL_peek_ex$FUNC, false
    );
    static final FunctionDescriptor SSL_write$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_write$MH = RuntimeHelper.downcallHandle(
        "SSL_write",
        constants$832.SSL_write$FUNC, false
    );
    static final FunctionDescriptor SSL_write_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_write_ex$MH = RuntimeHelper.downcallHandle(
        "SSL_write_ex",
        constants$832.SSL_write_ex$FUNC, false
    );
    static final FunctionDescriptor SSL_write_early_data$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_write_early_data$MH = RuntimeHelper.downcallHandle(
        "SSL_write_early_data",
        constants$832.SSL_write_early_data$FUNC, false
    );
    static final FunctionDescriptor SSL_ctrl$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_INT,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_ctrl$MH = RuntimeHelper.downcallHandle(
        "SSL_ctrl",
        constants$832.SSL_ctrl$FUNC, false
    );
}

