// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$487 {

    static final FunctionDescriptor sk_X509_NAME_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$487.sk_X509_NAME_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$487.sk_X509_NAME_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_num$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_num",
        constants$487.sk_X509_NAME_num$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_NAME_value$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_value",
        constants$487.sk_X509_NAME_value$FUNC, false
    );
    static final FunctionDescriptor sk_X509_NAME_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_NAME_new$MH = RuntimeHelper.downcallHandle(
        "sk_X509_NAME_new",
        constants$487.sk_X509_NAME_new$FUNC, false
    );
}


