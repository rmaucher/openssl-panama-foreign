// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1023 {

    static final FunctionDescriptor sk_X509_POLICY_NODE_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$1023.sk_X509_POLICY_NODE_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$1023.sk_X509_POLICY_NODE_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_num$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_num",
        constants$1023.sk_X509_POLICY_NODE_num$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_POLICY_NODE_value$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_value",
        constants$1023.sk_X509_POLICY_NODE_value$FUNC, false
    );
    static final FunctionDescriptor sk_X509_POLICY_NODE_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_POLICY_NODE_new$MH = RuntimeHelper.downcallHandle(
        "sk_X509_POLICY_NODE_new",
        constants$1023.sk_X509_POLICY_NODE_new$FUNC, false
    );
}


