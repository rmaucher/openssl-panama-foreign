// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$131 {

    static final FunctionDescriptor BIO_ADDRINFO_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle BIO_ADDRINFO_free$MH = RuntimeHelper.downcallHandle(
        "BIO_ADDRINFO_free",
        constants$131.BIO_ADDRINFO_free$FUNC, false
    );
    static final FunctionDescriptor BIO_parse_hostserv$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BIO_parse_hostserv$MH = RuntimeHelper.downcallHandle(
        "BIO_parse_hostserv",
        constants$131.BIO_parse_hostserv$FUNC, false
    );
    static final FunctionDescriptor BIO_lookup$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BIO_lookup$MH = RuntimeHelper.downcallHandle(
        "BIO_lookup",
        constants$131.BIO_lookup$FUNC, false
    );
    static final FunctionDescriptor BIO_lookup_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle BIO_lookup_ex$MH = RuntimeHelper.downcallHandle(
        "BIO_lookup_ex",
        constants$131.BIO_lookup_ex$FUNC, false
    );
    static final FunctionDescriptor BIO_sock_error$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_sock_error$MH = RuntimeHelper.downcallHandle(
        "BIO_sock_error",
        constants$131.BIO_sock_error$FUNC, false
    );
    static final FunctionDescriptor BIO_socket_ioctl$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle BIO_socket_ioctl$MH = RuntimeHelper.downcallHandle(
        "BIO_socket_ioctl",
        constants$131.BIO_socket_ioctl$FUNC, false
    );
}


