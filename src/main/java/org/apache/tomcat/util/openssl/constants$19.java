// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$19 {

    static final FunctionDescriptor SSL_CTX_get_client_CA_list$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_get_client_CA_list$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_get_client_CA_list",
        constants$19.SSL_CTX_get_client_CA_list$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_add_client_CA$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_add_client_CA$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_add_client_CA",
        constants$19.SSL_CTX_add_client_CA$FUNC, false
    );
    static final FunctionDescriptor SSL_set_connect_state$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle SSL_set_connect_state$MH = RuntimeHelper.downcallHandle(
        "SSL_set_connect_state",
        constants$19.SSL_set_connect_state$FUNC, false
    );
    static final FunctionDescriptor SSL_set_accept_state$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle SSL_set_accept_state$MH = RuntimeHelper.downcallHandle(
        "SSL_set_accept_state",
        constants$19.SSL_set_accept_state$FUNC, false
    );
    static final FunctionDescriptor SSL_get_privatekey$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_get_privatekey$MH = RuntimeHelper.downcallHandle(
        "SSL_get_privatekey",
        constants$19.SSL_get_privatekey$FUNC, false
    );
    static final FunctionDescriptor SSL_get_shutdown$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_get_shutdown$MH = RuntimeHelper.downcallHandle(
        "SSL_get_shutdown",
        constants$19.SSL_get_shutdown$FUNC, false
    );
}


