// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$560 {

    static final FunctionDescriptor X509_STORE_set_trust$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_STORE_set_trust$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_trust",
        constants$560.X509_STORE_set_trust$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_set1_param$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set1_param$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set1_param",
        constants$560.X509_STORE_set1_param$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get0_param$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get0_param$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get0_param",
        constants$560.X509_STORE_get0_param$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_set_verify$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_verify$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_verify",
        constants$560.X509_STORE_set_verify$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_CTX_set_verify$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_CTX_set_verify$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_CTX_set_verify",
        constants$560.X509_STORE_CTX_set_verify$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_verify$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_verify$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_verify",
        constants$560.X509_STORE_get_verify$FUNC, false
    );
}

