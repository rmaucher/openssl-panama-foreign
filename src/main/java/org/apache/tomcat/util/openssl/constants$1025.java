// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1025 {

    static final FunctionDescriptor sk_X509_POLICY_NODE_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_delete_ptr",
        constants$1025.sk_X509_POLICY_NODE_delete_ptr$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_push$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_push",
        constants$1025.sk_X509_POLICY_NODE_push$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_unshift",
        constants$1025.sk_X509_POLICY_NODE_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_pop$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_pop",
        constants$1025.sk_X509_POLICY_NODE_pop$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_shift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_shift",
        constants$1025.sk_X509_POLICY_NODE_shift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_pop_free",
        constants$1025.sk_X509_POLICY_NODE_pop_free$FUNC, false
    );
}


