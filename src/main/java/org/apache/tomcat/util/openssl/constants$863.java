// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$863 {

    static final FunctionDescriptor SSL_set_ct_validation_callback$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_set_ct_validation_callback$MH = RuntimeHelper.downcallHandle(
        "SSL_set_ct_validation_callback",
        constants$863.SSL_set_ct_validation_callback$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_ct_validation_callback$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_ct_validation_callback$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_ct_validation_callback",
        constants$863.SSL_CTX_set_ct_validation_callback$FUNC, false
    );
    static final FunctionDescriptor SSL_enable_ct$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_enable_ct$MH = RuntimeHelper.downcallHandle(
        "SSL_enable_ct",
        constants$863.SSL_enable_ct$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_enable_ct$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_CTX_enable_ct$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_enable_ct",
        constants$863.SSL_CTX_enable_ct$FUNC, false
    );
    static final FunctionDescriptor SSL_ct_is_enabled$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_ct_is_enabled$MH = RuntimeHelper.downcallHandle(
        "SSL_ct_is_enabled",
        constants$863.SSL_ct_is_enabled$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_ct_is_enabled$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_ct_is_enabled$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_ct_is_enabled",
        constants$863.SSL_CTX_ct_is_enabled$FUNC, false
    );
}


