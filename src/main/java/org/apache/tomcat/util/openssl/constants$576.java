// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$576 {

    static final FunctionDescriptor X509_STORE_CTX_get_by_subject$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_STORE_CTX_get_by_subject$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_CTX_get_by_subject",
        constants$576.X509_STORE_CTX_get_by_subject$FUNC, false
    );
    static final FunctionDescriptor X509_STORE_CTX_get_obj_by_subject$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_STORE_CTX_get_obj_by_subject$MH = RuntimeHelper.downcallHandle(
        "X509_STORE_CTX_get_obj_by_subject",
        constants$576.X509_STORE_CTX_get_obj_by_subject$FUNC, false
    );
    static final FunctionDescriptor X509_LOOKUP_ctrl$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_ctrl$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_ctrl",
        constants$576.X509_LOOKUP_ctrl$FUNC, false
    );
    static final FunctionDescriptor X509_load_cert_file$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_load_cert_file$MH = RuntimeHelper.downcallHandle(
        "X509_load_cert_file",
        constants$576.X509_load_cert_file$FUNC, false
    );
    static final FunctionDescriptor X509_load_crl_file$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_load_crl_file$MH = RuntimeHelper.downcallHandle(
        "X509_load_crl_file",
        constants$576.X509_load_crl_file$FUNC, false
    );
    static final FunctionDescriptor X509_load_cert_crl_file$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_load_cert_crl_file$MH = RuntimeHelper.downcallHandle(
        "X509_load_cert_crl_file",
        constants$576.X509_load_cert_crl_file$FUNC, false
    );
}


