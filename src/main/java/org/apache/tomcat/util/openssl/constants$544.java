// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$544 {

    static final FunctionDescriptor sk_X509_OBJECT_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_OBJECT_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_reserve",
        constants$544.sk_X509_OBJECT_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_free",
        constants$544.sk_X509_OBJECT_free$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_zero$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_zero",
        constants$544.sk_X509_OBJECT_zero$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_OBJECT_delete$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_delete",
        constants$544.sk_X509_OBJECT_delete$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_delete_ptr",
        constants$544.sk_X509_OBJECT_delete_ptr$FUNC, false
    );
    static final FunctionDescriptor sk_X509_OBJECT_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_OBJECT_push$MH = RuntimeHelper.downcallHandle(
        "sk_X509_OBJECT_push",
        constants$544.sk_X509_OBJECT_push$FUNC, false
    );
}


