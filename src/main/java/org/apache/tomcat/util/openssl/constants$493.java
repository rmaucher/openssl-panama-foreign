// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$493 {

    static final FunctionDescriptor sk_X509_EXTENSION_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_X509_EXTENSION_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_new_null",
        constants$493.sk_X509_EXTENSION_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_EXTENSION_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_new_reserve",
        constants$493.sk_X509_EXTENSION_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_EXTENSION_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_reserve",
        constants$493.sk_X509_EXTENSION_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_EXTENSION_free$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_free",
        constants$493.sk_X509_EXTENSION_free$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_EXTENSION_zero$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_zero",
        constants$493.sk_X509_EXTENSION_zero$FUNC, false
    );
    static final FunctionDescriptor sk_X509_EXTENSION_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_EXTENSION_delete$MH = RuntimeHelper.downcallHandle(
        "sk_X509_EXTENSION_delete",
        constants$493.sk_X509_EXTENSION_delete$FUNC, false
    );
}


