// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1032 {

    static final FunctionDescriptor sk_ASIdOrRange_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_dup$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_dup",
        constants$1032.sk_ASIdOrRange_dup$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_deep_copy",
        constants$1032.sk_ASIdOrRange_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_ASIdOrRange_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASIdOrRange_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_ASIdOrRange_set_cmp_func",
        constants$1032.sk_ASIdOrRange_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor ASRange_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ASRange_new$MH = RuntimeHelper.downcallHandle(
        "ASRange_new",
        constants$1032.ASRange_new$FUNC, false
    );
    static final FunctionDescriptor ASRange_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ASRange_free$MH = RuntimeHelper.downcallHandle(
        "ASRange_free",
        constants$1032.ASRange_free$FUNC, false
    );
    static final FunctionDescriptor d2i_ASRange$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ASRange$MH = RuntimeHelper.downcallHandle(
        "d2i_ASRange",
        constants$1032.d2i_ASRange$FUNC, false
    );
}

