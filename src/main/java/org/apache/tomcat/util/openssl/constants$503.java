// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$503 {

    static final FunctionDescriptor sk_X509_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_X509_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_X509_new_null",
        constants$503.sk_X509_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_X509_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_new_reserve",
        constants$503.sk_X509_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_reserve",
        constants$503.sk_X509_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_free",
        constants$503.sk_X509_free$FUNC, false
    );
    static final FunctionDescriptor sk_X509_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_zero$MH = RuntimeHelper.downcallHandle(
        "sk_X509_zero",
        constants$503.sk_X509_zero$FUNC, false
    );
    static final FunctionDescriptor sk_X509_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_delete$MH = RuntimeHelper.downcallHandle(
        "sk_X509_delete",
        constants$503.sk_X509_delete$FUNC, false
    );
}

