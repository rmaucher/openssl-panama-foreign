// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$561 {

    static final FunctionDescriptor X509_STORE_set_verify_cb$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_verify_cb$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_verify_cb",
        constants$561.X509_STORE_set_verify_cb$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_verify_cb$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_verify_cb$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_verify_cb",
        constants$561.X509_STORE_get_verify_cb$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_set_get_issuer$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_get_issuer$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_get_issuer",
        constants$561.X509_STORE_set_get_issuer$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_get_issuer$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_get_issuer$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_get_issuer",
        constants$561.X509_STORE_get_get_issuer$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_set_check_issued$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_set_check_issued$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_set_check_issued",
        constants$561.X509_STORE_set_check_issued$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_get_check_issued$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_get_check_issued$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_get_check_issued",
        constants$561.X509_STORE_get_check_issued$FUNC, false
    );
}

