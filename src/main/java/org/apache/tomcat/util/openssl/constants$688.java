// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$688 {

    static final FunctionDescriptor X509_NAME_ENTRY_get_object$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_NAME_ENTRY_get_object$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_get_object",
        constants$688.X509_NAME_ENTRY_get_object$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_get_data$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_NAME_ENTRY_get_data$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_get_data",
        constants$688.X509_NAME_ENTRY_get_data$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_set$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_NAME_ENTRY_set$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_set",
        constants$688.X509_NAME_ENTRY_set$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_get0_der$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_NAME_get0_der$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_get0_der",
        constants$688.X509_NAME_get0_der$FUNC, false
    );
    static final FunctionDescriptor X509v3_get_ext_count$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509v3_get_ext_count$MH = RuntimeHelper.downcallHandle(
        "X509v3_get_ext_count",
        constants$688.X509v3_get_ext_count$FUNC, false
    );
    static final FunctionDescriptor X509v3_get_ext_by_NID$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle X509v3_get_ext_by_NID$MH = RuntimeHelper.downcallHandle(
        "X509v3_get_ext_by_NID",
        constants$688.X509v3_get_ext_by_NID$FUNC, false
    );
}

