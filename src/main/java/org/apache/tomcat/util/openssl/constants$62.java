// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$62 {

    static final FunctionDescriptor sk_void_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_void_num$MH = RuntimeHelper.downcallHandle(
        "sk_void_num",
        constants$62.sk_void_num$FUNC, false
    );
    static final FunctionDescriptor sk_void_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_void_value$MH = RuntimeHelper.downcallHandle(
        "sk_void_value",
        constants$62.sk_void_value$FUNC, false
    );
    static final FunctionDescriptor sk_void_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_void_new$MH = RuntimeHelper.downcallHandle(
        "sk_void_new",
        constants$62.sk_void_new$FUNC, false
    );
    static final FunctionDescriptor sk_void_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_void_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_void_new_null",
        constants$62.sk_void_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_void_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_void_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_void_new_reserve",
        constants$62.sk_void_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_void_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_void_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_void_reserve",
        constants$62.sk_void_reserve$FUNC, false
    );
}

