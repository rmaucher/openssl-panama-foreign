// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$563 {

    static final FunctionDescriptor X509_STORE_set_cert_crl$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_cert_crl$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_cert_crl",
        constants$563.X509_STORE_set_cert_crl$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_cert_crl$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_cert_crl$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_cert_crl",
        constants$563.X509_STORE_get_cert_crl$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_set_check_policy$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_check_policy$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_check_policy",
        constants$563.X509_STORE_set_check_policy$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_check_policy$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_check_policy$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_check_policy",
        constants$563.X509_STORE_get_check_policy$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_set_lookup_certs$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_lookup_certs$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_lookup_certs",
        constants$563.X509_STORE_set_lookup_certs$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_lookup_certs$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_lookup_certs$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_lookup_certs",
        constants$563.X509_STORE_get_lookup_certs$FUNC, false
    );
}

