// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$72 {

    static final FunctionDescriptor CRYPTO_get_mem_functions$f$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle CRYPTO_get_mem_functions$f$MH = RuntimeHelper.downcallHandle(
        constants$72.CRYPTO_get_mem_functions$f$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_get_mem_functions$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle CRYPTO_get_mem_functions$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_get_mem_functions",
        constants$72.CRYPTO_get_mem_functions$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_malloc$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_LONG,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle CRYPTO_malloc$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_malloc",
        constants$72.CRYPTO_malloc$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_zalloc$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_LONG,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle CRYPTO_zalloc$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_zalloc",
        constants$72.CRYPTO_zalloc$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_memdup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle CRYPTO_memdup$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_memdup",
        constants$72.CRYPTO_memdup$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_strdup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle CRYPTO_strdup$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_strdup",
        constants$72.CRYPTO_strdup$FUNC, false
    );
}

