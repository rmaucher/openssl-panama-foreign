// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$545 {

    static final FunctionDescriptor sk_X509_OBJECT_unshift$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_unshift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_unshift",
        constants$545.sk_X509_OBJECT_unshift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_pop$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_pop",
        constants$545.sk_X509_OBJECT_pop$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_shift$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_shift",
        constants$545.sk_X509_OBJECT_shift$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_pop_free",
        constants$545.sk_X509_OBJECT_pop_free$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_OBJECT_insert$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_insert",
        constants$545.sk_X509_OBJECT_insert$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_set$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_set",
        constants$545.sk_X509_OBJECT_set$FUNC, false
    );
}


