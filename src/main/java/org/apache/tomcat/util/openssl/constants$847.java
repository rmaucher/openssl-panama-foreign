// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$847 {

    static final FunctionDescriptor SSL_set_shutdown$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_set_shutdown$MH = RuntimeHelper.downcallHandle(
        "SSL_set_shutdown",
        constants$847.SSL_set_shutdown$FUNC, false
    );
    static final FunctionDescriptor SSL_get_shutdown$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_get_shutdown$MH = RuntimeHelper.downcallHandle(
        "SSL_get_shutdown",
        constants$847.SSL_get_shutdown$FUNC, false
    );
    static final FunctionDescriptor SSL_version$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_version$MH = RuntimeHelper.downcallHandle(
        "SSL_version",
        constants$847.SSL_version$FUNC, false
    );
    static final FunctionDescriptor SSL_client_version$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_client_version$MH = RuntimeHelper.downcallHandle(
        "SSL_client_version",
        constants$847.SSL_client_version$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_default_verify_paths$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_default_verify_paths$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_default_verify_paths",
        constants$847.SSL_CTX_set_default_verify_paths$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_default_verify_dir$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_default_verify_dir$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_default_verify_dir",
        constants$847.SSL_CTX_set_default_verify_dir$FUNC, false
    );
}

