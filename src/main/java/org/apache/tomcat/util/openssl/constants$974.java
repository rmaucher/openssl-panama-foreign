// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$974 {

    static final FunctionDescriptor sk_POLICY_MAPPING_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_POLICY_MAPPING_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_POLICY_MAPPING_unshift",
        constants$974.sk_POLICY_MAPPING_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_POLICY_MAPPING_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_POLICY_MAPPING_pop$MH = RuntimeHelper.downcallHandle(
        "sk_POLICY_MAPPING_pop",
        constants$974.sk_POLICY_MAPPING_pop$FUNC, false
    );
    static final FunctionDescriptor sk_POLICY_MAPPING_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_POLICY_MAPPING_shift$MH = RuntimeHelper.downcallHandle(
        "sk_POLICY_MAPPING_shift",
        constants$974.sk_POLICY_MAPPING_shift$FUNC, false
    );
    static final FunctionDescriptor sk_POLICY_MAPPING_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_POLICY_MAPPING_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_POLICY_MAPPING_pop_free",
        constants$974.sk_POLICY_MAPPING_pop_free$FUNC, false
    );
    static final FunctionDescriptor sk_POLICY_MAPPING_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_POLICY_MAPPING_insert$MH = RuntimeHelper.downcallHandle(
        "sk_POLICY_MAPPING_insert",
        constants$974.sk_POLICY_MAPPING_insert$FUNC, false
    );
    static final FunctionDescriptor sk_POLICY_MAPPING_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_POLICY_MAPPING_set$MH = RuntimeHelper.downcallHandle(
        "sk_POLICY_MAPPING_set",
        constants$974.sk_POLICY_MAPPING_set$FUNC, false
    );
}

