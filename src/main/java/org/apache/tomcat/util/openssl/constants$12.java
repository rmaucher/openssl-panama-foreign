// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$12 {

    static final FunctionDescriptor at_quick_exit$__func$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle at_quick_exit$__func$MH = RuntimeHelper.downcallHandle(
        constants$12.at_quick_exit$__func$FUNC, false
    );
    static final FunctionDescriptor at_quick_exit$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle at_quick_exit$MH = RuntimeHelper.downcallHandle(
        "at_quick_exit",
        constants$12.at_quick_exit$FUNC, false
    );
    static final FunctionDescriptor on_exit$__func$FUNC = FunctionDescriptor.ofVoid(
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle on_exit$__func$MH = RuntimeHelper.downcallHandle(
        constants$12.on_exit$__func$FUNC, false
    );
    static final FunctionDescriptor on_exit$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle on_exit$MH = RuntimeHelper.downcallHandle(
        "on_exit",
        constants$12.on_exit$FUNC, false
    );
    static final FunctionDescriptor exit$FUNC = FunctionDescriptor.ofVoid(
        JAVA_INT
    );
    static final MethodHandle exit$MH = RuntimeHelper.downcallHandle(
        "exit",
        constants$12.exit$FUNC, false
    );
}

