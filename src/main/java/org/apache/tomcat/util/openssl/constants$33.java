// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$33 {

    static final FunctionDescriptor putc_unlocked$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle putc_unlocked$MH = RuntimeHelper.downcallHandle(
        "putc_unlocked",
        constants$33.putc_unlocked$FUNC, false
    );
    static final FunctionDescriptor putchar_unlocked$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle putchar_unlocked$MH = RuntimeHelper.downcallHandle(
        "putchar_unlocked",
        constants$33.putchar_unlocked$FUNC, false
    );
    static final FunctionDescriptor getw$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle getw$MH = RuntimeHelper.downcallHandle(
        "getw",
        constants$33.getw$FUNC, false
    );
    static final FunctionDescriptor putw$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle putw$MH = RuntimeHelper.downcallHandle(
        "putw",
        constants$33.putw$FUNC, false
    );
    static final FunctionDescriptor fgets$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle fgets$MH = RuntimeHelper.downcallHandle(
        "fgets",
        constants$33.fgets$FUNC, false
    );
    static final FunctionDescriptor __getdelim$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle __getdelim$MH = RuntimeHelper.downcallHandle(
        "__getdelim",
        constants$33.__getdelim$FUNC, false
    );
}

