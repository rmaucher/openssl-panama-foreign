// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$945 {

    static final FunctionDescriptor sk_GENERAL_NAMES_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_find$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_find",
        constants$945.sk_GENERAL_NAMES_find$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_find_ex$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_find_ex",
        constants$945.sk_GENERAL_NAMES_find_ex$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_sort$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_sort",
        constants$945.sk_GENERAL_NAMES_sort$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_is_sorted",
        constants$945.sk_GENERAL_NAMES_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_dup$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_dup",
        constants$945.sk_GENERAL_NAMES_dup$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_NAMES_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_NAMES_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_NAMES_deep_copy",
        constants$945.sk_GENERAL_NAMES_deep_copy$FUNC, false
    );
}


