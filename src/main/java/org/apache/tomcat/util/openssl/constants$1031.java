// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1031 {

    static final FunctionDescriptor sk_ASIdOrRange_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASIdOrRange_insert$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_insert",
        constants$1031.sk_ASIdOrRange_insert$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_set$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_set",
        constants$1031.sk_ASIdOrRange_set$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_find$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_find",
        constants$1031.sk_ASIdOrRange_find$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_find_ex$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_find_ex",
        constants$1031.sk_ASIdOrRange_find_ex$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_sort$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_sort",
        constants$1031.sk_ASIdOrRange_sort$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_is_sorted",
        constants$1031.sk_ASIdOrRange_is_sorted$FUNC, false
    );
}

