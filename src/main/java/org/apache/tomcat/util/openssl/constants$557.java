// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$557 {

    static final FunctionDescriptor X509_OBJECT_up_ref_count$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_OBJECT_up_ref_count$MH = RuntimeHelper.downcallHandle(
        "X509_OBJECT_up_ref_count",
        constants$557.X509_OBJECT_up_ref_count$FUNC, false
    );
    static final FunctionDescriptor X509_OBJECT_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_OBJECT_new$MH = RuntimeHelper.downcallHandle(
        "X509_OBJECT_new",
        constants$557.X509_OBJECT_new$FUNC, false
    );
    static final FunctionDescriptor X509_OBJECT_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_OBJECT_free$MH = RuntimeHelper.downcallHandle(
        "X509_OBJECT_free",
        constants$557.X509_OBJECT_free$FUNC, false
    );
    static final FunctionDescriptor X509_OBJECT_get_type$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_OBJECT_get_type$MH = RuntimeHelper.downcallHandle(
        "X509_OBJECT_get_type",
        constants$557.X509_OBJECT_get_type$FUNC, false
    );
    static final FunctionDescriptor X509_OBJECT_get0_X509$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_OBJECT_get0_X509$MH = RuntimeHelper.downcallHandle(
        "X509_OBJECT_get0_X509",
        constants$557.X509_OBJECT_get0_X509$FUNC, false
    );
    static final FunctionDescriptor X509_OBJECT_set1_X509$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_OBJECT_set1_X509$MH = RuntimeHelper.downcallHandle(
        "X509_OBJECT_set1_X509",
        constants$557.X509_OBJECT_set1_X509$FUNC, false
    );
}

