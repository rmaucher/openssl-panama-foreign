// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$910 {

    static final FunctionDescriptor sk_CONF_MODULE_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$910.sk_CONF_MODULE_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$910.sk_CONF_MODULE_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_num$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_num",
        constants$910.sk_CONF_MODULE_num$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_CONF_MODULE_value$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_value",
        constants$910.sk_CONF_MODULE_value$FUNC, false
    );
}

