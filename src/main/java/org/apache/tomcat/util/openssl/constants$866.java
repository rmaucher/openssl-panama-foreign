// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$866 {

    static final FunctionDescriptor SSL_get0_security_ex_data$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_get0_security_ex_data$MH = RuntimeHelper.downcallHandle(
        "SSL_get0_security_ex_data",
        constants$866.SSL_get0_security_ex_data$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_security_level$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_CTX_set_security_level$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_security_level",
        constants$866.SSL_CTX_set_security_level$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_get_security_level$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_get_security_level$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_get_security_level",
        constants$866.SSL_CTX_get_security_level$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_security_callback$cb$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_security_callback$cb$MH = RuntimeHelper.downcallHandle(
        constants$866.SSL_CTX_set_security_callback$cb$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_security_callback$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_security_callback$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_security_callback",
        constants$866.SSL_CTX_set_security_callback$FUNC, false
    );
}


