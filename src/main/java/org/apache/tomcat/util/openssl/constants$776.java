// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$776 {

    static final FunctionDescriptor SSL_use_psk_identity_hint$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_use_psk_identity_hint$MH = RuntimeHelper.downcallHandle(
        "SSL_use_psk_identity_hint",
        constants$776.SSL_use_psk_identity_hint$FUNC, false
    );
    static final FunctionDescriptor SSL_get_psk_identity_hint$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_get_psk_identity_hint$MH = RuntimeHelper.downcallHandle(
        "SSL_get_psk_identity_hint",
        constants$776.SSL_get_psk_identity_hint$FUNC, false
    );
    static final FunctionDescriptor SSL_get_psk_identity$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_get_psk_identity$MH = RuntimeHelper.downcallHandle(
        "SSL_get_psk_identity",
        constants$776.SSL_get_psk_identity$FUNC, false
    );
    static final FunctionDescriptor SSL_psk_find_session_cb_func$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SSL_psk_find_session_cb_func$MH = RuntimeHelper.downcallHandle(
        constants$776.SSL_psk_find_session_cb_func$FUNC, false
    );
    static final FunctionDescriptor SSL_psk_use_session_cb_func$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
}

