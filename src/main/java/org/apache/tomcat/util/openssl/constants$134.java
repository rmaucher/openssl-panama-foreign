// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$134 {

    static final FunctionDescriptor BIO_listen$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BIO_listen$MH = RuntimeHelper.downcallHandle(
        "BIO_listen",
        constants$134.BIO_listen$FUNC, false
    );
    static final FunctionDescriptor BIO_accept_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BIO_accept_ex$MH = RuntimeHelper.downcallHandle(
        "BIO_accept_ex",
        constants$134.BIO_accept_ex$FUNC, false
    );
    static final FunctionDescriptor BIO_closesocket$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_closesocket$MH = RuntimeHelper.downcallHandle(
        "BIO_closesocket",
        constants$134.BIO_closesocket$FUNC, false
    );
    static final FunctionDescriptor BIO_new_socket$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_new_socket$MH = RuntimeHelper.downcallHandle(
        "BIO_new_socket",
        constants$134.BIO_new_socket$FUNC, false
    );
    static final FunctionDescriptor BIO_new_connect$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_new_connect$MH = RuntimeHelper.downcallHandle(
        "BIO_new_connect",
        constants$134.BIO_new_connect$FUNC, false
    );
    static final FunctionDescriptor BIO_new_accept$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_new_accept$MH = RuntimeHelper.downcallHandle(
        "BIO_new_accept",
        constants$134.BIO_new_accept$FUNC, false
    );
}

