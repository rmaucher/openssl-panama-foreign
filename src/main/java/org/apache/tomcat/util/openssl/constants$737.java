// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$737 {

    static final FunctionDescriptor sk_SCT_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_SCT_new$MH = RuntimeHelper.downcallHandle(
        "sk_SCT_new",
        constants$737.sk_SCT_new$FUNC, false
    );
    static final FunctionDescriptor sk_SCT_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_SCT_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_SCT_new_null",
        constants$737.sk_SCT_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_SCT_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_SCT_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_SCT_new_reserve",
        constants$737.sk_SCT_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_SCT_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_SCT_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_SCT_reserve",
        constants$737.sk_SCT_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_SCT_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_SCT_free$MH = RuntimeHelper.downcallHandle(
        "sk_SCT_free",
        constants$737.sk_SCT_free$FUNC, false
    );
    static final FunctionDescriptor sk_SCT_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_SCT_zero$MH = RuntimeHelper.downcallHandle(
        "sk_SCT_zero",
        constants$737.sk_SCT_zero$FUNC, false
    );
}

