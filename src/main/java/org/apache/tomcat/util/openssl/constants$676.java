// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$676 {

    static final FunctionDescriptor X509_CRL_set_issuer_name$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_CRL_set_issuer_name$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_set_issuer_name",
        constants$676.X509_CRL_set_issuer_name$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_set1_lastUpdate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_CRL_set1_lastUpdate$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_set1_lastUpdate",
        constants$676.X509_CRL_set1_lastUpdate$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_set1_nextUpdate$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_CRL_set1_nextUpdate$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_set1_nextUpdate",
        constants$676.X509_CRL_set1_nextUpdate$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_sort$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_CRL_sort$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_sort",
        constants$676.X509_CRL_sort$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_up_ref$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_CRL_up_ref$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_up_ref",
        constants$676.X509_CRL_up_ref$FUNC, false
    );
    static final FunctionDescriptor X509_CRL_get_version$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle X509_CRL_get_version$MH = RuntimeHelper.downcallHandle(
        "X509_CRL_get_version",
        constants$676.X509_CRL_get_version$FUNC, false
    );
}

