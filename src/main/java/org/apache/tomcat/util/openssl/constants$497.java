// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$497 {

    static final FunctionDescriptor sk_X509_ATTRIBUTE_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$497.sk_X509_ATTRIBUTE_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$497.sk_X509_ATTRIBUTE_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_num$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_num",
        constants$497.sk_X509_ATTRIBUTE_num$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_ATTRIBUTE_value$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_value",
        constants$497.sk_X509_ATTRIBUTE_value$FUNC, false
    );
    static final FunctionDescriptor sk_X509_ATTRIBUTE_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_ATTRIBUTE_new$MH = RuntimeHelper.downcallHandle(
        "sk_X509_ATTRIBUTE_new",
        constants$497.sk_X509_ATTRIBUTE_new$FUNC, false
    );
}

