// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1055 {

    static final FunctionDescriptor sk_ASN1_STRING_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_find_ex$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_find_ex",
        constants$1055.sk_ASN1_STRING_find_ex$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_sort$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_sort",
        constants$1055.sk_ASN1_STRING_sort$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_is_sorted",
        constants$1055.sk_ASN1_STRING_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_dup$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_dup",
        constants$1055.sk_ASN1_STRING_dup$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_deep_copy",
        constants$1055.sk_ASN1_STRING_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_set_cmp_func",
        constants$1055.sk_ASN1_STRING_set_cmp_func$FUNC, false
    );
}

