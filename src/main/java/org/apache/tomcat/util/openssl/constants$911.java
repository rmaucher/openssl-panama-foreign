// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$911 {

    static final FunctionDescriptor sk_CONF_MODULE_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_new$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_new",
        constants$911.sk_CONF_MODULE_new$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_CONF_MODULE_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_new_null",
        constants$911.sk_CONF_MODULE_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_CONF_MODULE_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_new_reserve",
        constants$911.sk_CONF_MODULE_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_CONF_MODULE_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_reserve",
        constants$911.sk_CONF_MODULE_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_free$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_free",
        constants$911.sk_CONF_MODULE_free$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_zero$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_zero",
        constants$911.sk_CONF_MODULE_zero$FUNC, false
    );
}


