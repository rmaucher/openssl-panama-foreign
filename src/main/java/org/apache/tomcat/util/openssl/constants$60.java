// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$60 {

    static final FunctionDescriptor CRYPTO_THREAD_lock_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle CRYPTO_THREAD_lock_new$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_THREAD_lock_new",
        constants$60.CRYPTO_THREAD_lock_new$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_THREAD_read_lock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle CRYPTO_THREAD_read_lock$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_THREAD_read_lock",
        constants$60.CRYPTO_THREAD_read_lock$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_THREAD_write_lock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle CRYPTO_THREAD_write_lock$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_THREAD_write_lock",
        constants$60.CRYPTO_THREAD_write_lock$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_THREAD_unlock$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle CRYPTO_THREAD_unlock$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_THREAD_unlock",
        constants$60.CRYPTO_THREAD_unlock$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_THREAD_lock_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle CRYPTO_THREAD_lock_free$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_THREAD_lock_free",
        constants$60.CRYPTO_THREAD_lock_free$FUNC, false
    );
    static final FunctionDescriptor CRYPTO_atomic_add$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle CRYPTO_atomic_add$MH = RuntimeHelper.downcallHandle(
        "CRYPTO_atomic_add",
        constants$60.CRYPTO_atomic_add$FUNC, false
    );
}

