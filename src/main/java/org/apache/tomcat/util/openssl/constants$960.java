// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$960 {

    static final FunctionDescriptor sk_SXNETID_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_SXNETID_find$MH = RuntimeHelper.downcallHandle(
        "sk_SXNETID_find",
        constants$960.sk_SXNETID_find$FUNC, false
    );
    static final FunctionDescriptor sk_SXNETID_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_SXNETID_find_ex$MH = RuntimeHelper.downcallHandle(
        "sk_SXNETID_find_ex",
        constants$960.sk_SXNETID_find_ex$FUNC, false
    );
    static final FunctionDescriptor sk_SXNETID_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_SXNETID_sort$MH = RuntimeHelper.downcallHandle(
        "sk_SXNETID_sort",
        constants$960.sk_SXNETID_sort$FUNC, false
    );
    static final FunctionDescriptor sk_SXNETID_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_SXNETID_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_SXNETID_is_sorted",
        constants$960.sk_SXNETID_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_SXNETID_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_SXNETID_dup$MH = RuntimeHelper.downcallHandle(
        "sk_SXNETID_dup",
        constants$960.sk_SXNETID_dup$FUNC, false
    );
    static final FunctionDescriptor sk_SXNETID_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_SXNETID_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_SXNETID_deep_copy",
        constants$960.sk_SXNETID_deep_copy$FUNC, false
    );
}

