// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$855 {

    static final FunctionDescriptor SSL_CIPHER_find$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CIPHER_find$MH = RuntimeHelper.downcallHandle(
        "SSL_CIPHER_find",
        constants$855.SSL_CIPHER_find$FUNC, false
    );
    static final FunctionDescriptor SSL_CIPHER_get_cipher_nid$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CIPHER_get_cipher_nid$MH = RuntimeHelper.downcallHandle(
        "SSL_CIPHER_get_cipher_nid",
        constants$855.SSL_CIPHER_get_cipher_nid$FUNC, false
    );
    static final FunctionDescriptor SSL_CIPHER_get_digest_nid$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CIPHER_get_digest_nid$MH = RuntimeHelper.downcallHandle(
        "SSL_CIPHER_get_digest_nid",
        constants$855.SSL_CIPHER_get_digest_nid$FUNC, false
    );
    static final FunctionDescriptor SSL_bytes_to_cipher_list$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_bytes_to_cipher_list$MH = RuntimeHelper.downcallHandle(
        "SSL_bytes_to_cipher_list",
        constants$855.SSL_bytes_to_cipher_list$FUNC, false
    );
    static final FunctionDescriptor SSL_set_session_ticket_ext$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_set_session_ticket_ext$MH = RuntimeHelper.downcallHandle(
        "SSL_set_session_ticket_ext",
        constants$855.SSL_set_session_ticket_ext$FUNC, false
    );
    static final FunctionDescriptor SSL_set_session_ticket_ext_cb$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_set_session_ticket_ext_cb$MH = RuntimeHelper.downcallHandle(
        "SSL_set_session_ticket_ext_cb",
        constants$855.SSL_set_session_ticket_ext_cb$FUNC, false
    );
}

