// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$983 {

    static final FunctionDescriptor sk_X509_PURPOSE_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_PURPOSE_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$983.sk_X509_PURPOSE_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_PURPOSE_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_PURPOSE_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$983.sk_X509_PURPOSE_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_X509_PURPOSE_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_PURPOSE_num$MH = RuntimeHelper.downcallHandle(
        "sk_X509_PURPOSE_num",
        constants$983.sk_X509_PURPOSE_num$FUNC, false
    );
    static final FunctionDescriptor sk_X509_PURPOSE_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_PURPOSE_value$MH = RuntimeHelper.downcallHandle(
        "sk_X509_PURPOSE_value",
        constants$983.sk_X509_PURPOSE_value$FUNC, false
    );
    static final FunctionDescriptor sk_X509_PURPOSE_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_PURPOSE_new$MH = RuntimeHelper.downcallHandle(
        "sk_X509_PURPOSE_new",
        constants$983.sk_X509_PURPOSE_new$FUNC, false
    );
}

