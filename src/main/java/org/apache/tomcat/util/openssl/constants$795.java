// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$795 {

    static final FunctionDescriptor BIO_new_ssl$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle BIO_new_ssl$MH = RuntimeHelper.downcallHandle(
        "BIO_new_ssl",
        constants$795.BIO_new_ssl$FUNC, false
    );
    static final FunctionDescriptor BIO_new_ssl_connect$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_new_ssl_connect$MH = RuntimeHelper.downcallHandle(
        "BIO_new_ssl_connect",
        constants$795.BIO_new_ssl_connect$FUNC, false
    );
    static final FunctionDescriptor BIO_new_buffer_ssl_connect$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_new_buffer_ssl_connect$MH = RuntimeHelper.downcallHandle(
        "BIO_new_buffer_ssl_connect",
        constants$795.BIO_new_buffer_ssl_connect$FUNC, false
    );
    static final FunctionDescriptor BIO_ssl_copy_session_id$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle BIO_ssl_copy_session_id$MH = RuntimeHelper.downcallHandle(
        "BIO_ssl_copy_session_id",
        constants$795.BIO_ssl_copy_session_id$FUNC, false
    );
    static final FunctionDescriptor BIO_ssl_shutdown$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle BIO_ssl_shutdown$MH = RuntimeHelper.downcallHandle(
        "BIO_ssl_shutdown",
        constants$795.BIO_ssl_shutdown$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_cipher_list$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_cipher_list$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_cipher_list",
        constants$795.SSL_CTX_set_cipher_list$FUNC, false
    );
}


