// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$820 {

    static final FunctionDescriptor SSL_get_default_passwd_cb_userdata$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_get_default_passwd_cb_userdata$MH = RuntimeHelper.downcallHandle(
        "SSL_get_default_passwd_cb_userdata",
        constants$820.SSL_get_default_passwd_cb_userdata$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_check_private_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_check_private_key$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_check_private_key",
        constants$820.SSL_CTX_check_private_key$FUNC, false
    );
    static final FunctionDescriptor SSL_check_private_key$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_check_private_key$MH = RuntimeHelper.downcallHandle(
        "SSL_check_private_key",
        constants$820.SSL_check_private_key$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set_session_id_context$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_CTX_set_session_id_context$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set_session_id_context",
        constants$820.SSL_CTX_set_session_id_context$FUNC, false
    );
    static final FunctionDescriptor SSL_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_new$MH = RuntimeHelper.downcallHandle(
        "SSL_new",
        constants$820.SSL_new$FUNC, false
    );
    static final FunctionDescriptor SSL_up_ref$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SSL_up_ref$MH = RuntimeHelper.downcallHandle(
        "SSL_up_ref",
        constants$820.SSL_up_ref$FUNC, false
    );
}

