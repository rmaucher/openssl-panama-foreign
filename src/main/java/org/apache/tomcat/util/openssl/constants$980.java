// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$980 {

    static final FunctionDescriptor sk_GENERAL_SUBTREE_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_SUBTREE_find$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_SUBTREE_find",
        constants$980.sk_GENERAL_SUBTREE_find$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_SUBTREE_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_SUBTREE_find_ex$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_SUBTREE_find_ex",
        constants$980.sk_GENERAL_SUBTREE_find_ex$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_SUBTREE_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_SUBTREE_sort$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_SUBTREE_sort",
        constants$980.sk_GENERAL_SUBTREE_sort$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_SUBTREE_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_SUBTREE_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_SUBTREE_is_sorted",
        constants$980.sk_GENERAL_SUBTREE_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_SUBTREE_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_SUBTREE_dup$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_SUBTREE_dup",
        constants$980.sk_GENERAL_SUBTREE_dup$FUNC, false
    );
    static final FunctionDescriptor sk_GENERAL_SUBTREE_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_GENERAL_SUBTREE_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_GENERAL_SUBTREE_deep_copy",
        constants$980.sk_GENERAL_SUBTREE_deep_copy$FUNC, false
    );
}

