// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$842 {

    static final FunctionDescriptor SSL_alert_type_string$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_alert_type_string$MH = RuntimeHelper.downcallHandle(
        "SSL_alert_type_string",
        constants$842.SSL_alert_type_string$FUNC, false
    );
    static final FunctionDescriptor SSL_alert_desc_string_long$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_alert_desc_string_long$MH = RuntimeHelper.downcallHandle(
        "SSL_alert_desc_string_long",
        constants$842.SSL_alert_desc_string_long$FUNC, false
    );
    static final FunctionDescriptor SSL_alert_desc_string$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle SSL_alert_desc_string$MH = RuntimeHelper.downcallHandle(
        "SSL_alert_desc_string",
        constants$842.SSL_alert_desc_string$FUNC, false
    );
    static final FunctionDescriptor SSL_set0_CA_list$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_set0_CA_list$MH = RuntimeHelper.downcallHandle(
        "SSL_set0_CA_list",
        constants$842.SSL_set0_CA_list$FUNC, false
    );
    static final FunctionDescriptor SSL_CTX_set0_CA_list$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_CTX_set0_CA_list$MH = RuntimeHelper.downcallHandle(
        "SSL_CTX_set0_CA_list",
        constants$842.SSL_CTX_set0_CA_list$FUNC, false
    );
    static final FunctionDescriptor SSL_get0_CA_list$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle SSL_get0_CA_list$MH = RuntimeHelper.downcallHandle(
        "SSL_get0_CA_list",
        constants$842.SSL_get0_CA_list$FUNC, false
    );
}


