// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$126 {

    static final FunctionDescriptor BIO_sock_should_retry$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_sock_should_retry$MH = RuntimeHelper.downcallHandle(
        "BIO_sock_should_retry",
        constants$126.BIO_sock_should_retry$FUNC, false
    );
    static final FunctionDescriptor BIO_sock_non_fatal_error$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_sock_non_fatal_error$MH = RuntimeHelper.downcallHandle(
        "BIO_sock_non_fatal_error",
        constants$126.BIO_sock_non_fatal_error$FUNC, false
    );
    static final FunctionDescriptor BIO_fd_should_retry$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_fd_should_retry$MH = RuntimeHelper.downcallHandle(
        "BIO_fd_should_retry",
        constants$126.BIO_fd_should_retry$FUNC, false
    );
    static final FunctionDescriptor BIO_fd_non_fatal_error$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle BIO_fd_non_fatal_error$MH = RuntimeHelper.downcallHandle(
        "BIO_fd_non_fatal_error",
        constants$126.BIO_fd_non_fatal_error$FUNC, false
    );
    static final FunctionDescriptor BIO_dump_cb$cb$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle BIO_dump_cb$cb$MH = RuntimeHelper.downcallHandle(
        constants$126.BIO_dump_cb$cb$FUNC, false
    );
}


