// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$520 {

    static final FunctionDescriptor sk_X509_CRL_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_X509_CRL_insert$MH = RuntimeHelper.downcallHandle(
        "sk_X509_CRL_insert",
        constants$520.sk_X509_CRL_insert$FUNC, false
    );
    static final FunctionDescriptor sk_X509_CRL_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_CRL_set$MH = RuntimeHelper.downcallHandle(
        "sk_X509_CRL_set",
        constants$520.sk_X509_CRL_set$FUNC, false
    );
    static final FunctionDescriptor sk_X509_CRL_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_CRL_find$MH = RuntimeHelper.downcallHandle(
        "sk_X509_CRL_find",
        constants$520.sk_X509_CRL_find$FUNC, false
    );
    static final FunctionDescriptor sk_X509_CRL_find_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_X509_CRL_find_ex$MH = RuntimeHelper.downcallHandle(
        "sk_X509_CRL_find_ex",
        constants$520.sk_X509_CRL_find_ex$FUNC, false
    );
    static final FunctionDescriptor sk_X509_CRL_sort$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_X509_CRL_sort$MH = RuntimeHelper.downcallHandle(
        "sk_X509_CRL_sort",
        constants$520.sk_X509_CRL_sort$FUNC, false
    );
    static final FunctionDescriptor sk_X509_CRL_is_sorted$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_X509_CRL_is_sorted$MH = RuntimeHelper.downcallHandle(
        "sk_X509_CRL_is_sorted",
        constants$520.sk_X509_CRL_is_sorted$FUNC, false
    );
}


