// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$35 {

    static final FunctionDescriptor fwrite$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_LONG,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle fwrite$MH = RuntimeHelper.downcallHandle(
        "fwrite",
        constants$35.fwrite$FUNC, false
    );
    static final FunctionDescriptor fread_unlocked$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_LONG,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle fread_unlocked$MH = RuntimeHelper.downcallHandle(
        "fread_unlocked",
        constants$35.fread_unlocked$FUNC, false
    );
    static final FunctionDescriptor fwrite_unlocked$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_LONG,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle fwrite_unlocked$MH = RuntimeHelper.downcallHandle(
        "fwrite_unlocked",
        constants$35.fwrite_unlocked$FUNC, false
    );
    static final FunctionDescriptor fseek$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        JAVA_INT
    );
    static final MethodHandle fseek$MH = RuntimeHelper.downcallHandle(
        "fseek",
        constants$35.fseek$FUNC, false
    );
    static final FunctionDescriptor ftell$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle ftell$MH = RuntimeHelper.downcallHandle(
        "ftell",
        constants$35.ftell$FUNC, false
    );
    static final FunctionDescriptor rewind$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle rewind$MH = RuntimeHelper.downcallHandle(
        "rewind",
        constants$35.rewind$FUNC, false
    );
}

