// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$132 {

    static final FunctionDescriptor BIO_socket_nbio$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_socket_nbio$MH = RuntimeHelper.downcallHandle(
        "BIO_socket_nbio",
        constants$132.BIO_socket_nbio$FUNC, false
    );
    static final FunctionDescriptor BIO_sock_init$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle BIO_sock_init$MH = RuntimeHelper.downcallHandle(
        "BIO_sock_init",
        constants$132.BIO_sock_init$FUNC, false
    );
    static final FunctionDescriptor BIO_set_tcp_ndelay$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_set_tcp_ndelay$MH = RuntimeHelper.downcallHandle(
        "BIO_set_tcp_ndelay",
        constants$132.BIO_set_tcp_ndelay$FUNC, false
    );
    static final FunctionDescriptor BIO_gethostbyname$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_gethostbyname$MH = RuntimeHelper.downcallHandle(
        "BIO_gethostbyname",
        constants$132.BIO_gethostbyname$FUNC, false
    );
    static final FunctionDescriptor BIO_get_port$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_get_port$MH = RuntimeHelper.downcallHandle(
        "BIO_get_port",
        constants$132.BIO_get_port$FUNC, false
    );
    static final FunctionDescriptor BIO_get_host_ip$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_get_host_ip$MH = RuntimeHelper.downcallHandle(
        "BIO_get_host_ip",
        constants$132.BIO_get_host_ip$FUNC, false
    );
}

