// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$857 {

    static final FunctionDescriptor SSL_set_not_resumable_session_callback$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_set_not_resumable_session_callback$MH = RuntimeHelper.downcallHandle(
        "SSL_set_not_resumable_session_callback",
        constants$857.SSL_set_not_resumable_session_callback$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_record_padding_callback$cb$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS,
        JAVA_INT,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_record_padding_callback$cb$MH = RuntimeHelper.downcallHandle(
        constants$857.SSL_CTX_set_record_padding_callback$cb$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_record_padding_callback$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_record_padding_callback$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_record_padding_callback",
        constants$857.SSL_CTX_set_record_padding_callback$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_record_padding_callback_arg$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set_record_padding_callback_arg$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_record_padding_callback_arg",
        constants$857.SSL_CTX_set_record_padding_callback_arg$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_get_record_padding_callback_arg$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_get_record_padding_callback_arg$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_get_record_padding_callback_arg",
        constants$857.SSL_CTX_get_record_padding_callback_arg$FUNC, false
    );
}


