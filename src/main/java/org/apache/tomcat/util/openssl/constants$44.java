// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$44 {

    static final FunctionDescriptor OPENSSL_sk_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_zero$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_zero",
        constants$44.OPENSSL_sk_zero$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_set_cmp_func",
        constants$44.OPENSSL_sk_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_dup$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_dup",
        constants$44.OPENSSL_sk_dup$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_sort$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_sort",
        constants$44.OPENSSL_sk_sort$FUNC, false
    );
    static final FunctionDescriptor OPENSSL_sk_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle OPENSSL_sk_is_sorted$MH = RuntimeHelper.downcallHandle(
        "OPENSSL_sk_is_sorted",
        constants$44.OPENSSL_sk_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_STRING_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
}


