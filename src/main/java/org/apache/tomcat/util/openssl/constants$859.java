// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$859 {

    static final FunctionDescriptor SSL_set_block_padding$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SSL_set_block_padding$MH = RuntimeHelper.downcallHandle(
        "SSL_set_block_padding",
        constants$859.SSL_set_block_padding$FUNC, false
    );
    static final FunctionDescriptor SSL_set_num_tickets$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SSL_set_num_tickets$MH = RuntimeHelper.downcallHandle(
        "SSL_set_num_tickets",
        constants$859.SSL_set_num_tickets$FUNC, false
    );
    static final FunctionDescriptor SSL_get_num_tickets$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_get_num_tickets$MH = RuntimeHelper.downcallHandle(
        "SSL_get_num_tickets",
        constants$859.SSL_get_num_tickets$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_num_tickets$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SSL_CTX_set_num_tickets$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_num_tickets",
        constants$859.SSL_CTX_set_num_tickets$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_get_num_tickets$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_get_num_tickets$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_get_num_tickets",
        constants$859.SSL_CTX_get_num_tickets$FUNC, false
    );
    static final FunctionDescriptor SSL_session_reused$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_session_reused$MH = RuntimeHelper.downcallHandle(
        "SSL_session_reused",
        constants$859.SSL_session_reused$FUNC, false
    );
}


