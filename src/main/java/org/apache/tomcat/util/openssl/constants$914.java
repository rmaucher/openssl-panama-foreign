// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$914 {

    static final FunctionDescriptor sk_CONF_MODULE_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_is_sorted",
        constants$914.sk_CONF_MODULE_is_sorted$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_dup$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_dup$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_dup",
        constants$914.sk_CONF_MODULE_dup$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_deep_copy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_deep_copy$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_deep_copy",
        constants$914.sk_CONF_MODULE_deep_copy$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_MODULE_set_cmp_func$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_CONF_MODULE_set_cmp_func$MH = RuntimeHelper.downcallHandle(
        "sk_CONF_MODULE_set_cmp_func",
        constants$914.sk_CONF_MODULE_set_cmp_func$FUNC, false
    );
    static final FunctionDescriptor sk_CONF_IMODULE_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_CONF_IMODULE_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$914.sk_CONF_IMODULE_compfunc$FUNC, false
    );
}


