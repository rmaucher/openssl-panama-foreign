// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$59 {

    static final FunctionDescriptor sk_OPENSSL_BLOCK_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_BLOCK_sort$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_BLOCK_sort",
        constants$59.sk_OPENSSL_BLOCK_sort$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_BLOCK_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_BLOCK_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_BLOCK_is_sorted",
        constants$59.sk_OPENSSL_BLOCK_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_BLOCK_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_BLOCK_dup$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_BLOCK_dup",
        constants$59.sk_OPENSSL_BLOCK_dup$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_BLOCK_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_BLOCK_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_BLOCK_deep_copy",
        constants$59.sk_OPENSSL_BLOCK_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_OPENSSL_BLOCK_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_OPENSSL_BLOCK_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_OPENSSL_BLOCK_set_cmp_func",
        constants$59.sk_OPENSSL_BLOCK_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor ERR_load_CRYPTO_strings$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_load_CRYPTO_strings$MH = RuntimeHelper.downcallHandle(
        "ERR_load_CRYPTO_strings",
        constants$59.ERR_load_CRYPTO_strings$FUNC, false
    );
}

