// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$550 {

    static final FunctionDescriptor sk_X509_VERIFY_PARAM_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_VERIFY_PARAM_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_VERIFY_PARAM_unshift",
        constants$550.sk_X509_VERIFY_PARAM_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_VERIFY_PARAM_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_VERIFY_PARAM_pop$MH = RuntimeHelper.downcallHandle(
        "sk_X509_VERIFY_PARAM_pop",
        constants$550.sk_X509_VERIFY_PARAM_pop$FUNC, false
    );
    static final FunctionDescriptor sk_X509_VERIFY_PARAM_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_VERIFY_PARAM_shift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_VERIFY_PARAM_shift",
        constants$550.sk_X509_VERIFY_PARAM_shift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_VERIFY_PARAM_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_VERIFY_PARAM_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_VERIFY_PARAM_pop_free",
        constants$550.sk_X509_VERIFY_PARAM_pop_free$FUNC, false
    );
    static final FunctionDescriptor sk_X509_VERIFY_PARAM_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_VERIFY_PARAM_insert$MH = RuntimeHelper.downcallHandle(
        "sk_X509_VERIFY_PARAM_insert",
        constants$550.sk_X509_VERIFY_PARAM_insert$FUNC, false
    );
    static final FunctionDescriptor sk_X509_VERIFY_PARAM_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_VERIFY_PARAM_set$MH = RuntimeHelper.downcallHandle(
        "sk_X509_VERIFY_PARAM_set",
        constants$550.sk_X509_VERIFY_PARAM_set$FUNC, false
    );
}

