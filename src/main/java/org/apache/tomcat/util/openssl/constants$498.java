// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$498 {

    static final FunctionDescriptor sk_X509_ATTRIBUTE_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_X509_ATTRIBUTE_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_new_null",
        constants$498.sk_X509_ATTRIBUTE_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_ATTRIBUTE_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_new_reserve",
        constants$498.sk_X509_ATTRIBUTE_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_ATTRIBUTE_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_reserve",
        constants$498.sk_X509_ATTRIBUTE_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_free",
        constants$498.sk_X509_ATTRIBUTE_free$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_zero$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_zero",
        constants$498.sk_X509_ATTRIBUTE_zero$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_ATTRIBUTE_delete$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_delete",
        constants$498.sk_X509_ATTRIBUTE_delete$FUNC, false
    );
}


