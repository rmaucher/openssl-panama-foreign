// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$674 {

    static final FunctionDescriptor X509_REQ_add_extensions_nid$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_REQ_add_extensions_nid$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_add_extensions_nid",
        constants$674.X509_REQ_add_extensions_nid$FUNC, false
    );
    static final FunctionDescriptor X509_REQ_add_extensions$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_REQ_add_extensions$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_add_extensions",
        constants$674.X509_REQ_add_extensions$FUNC, false
    );
    static final FunctionDescriptor X509_REQ_get_attr_count$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_REQ_get_attr_count$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_get_attr_count",
        constants$674.X509_REQ_get_attr_count$FUNC, false
    );
    static final FunctionDescriptor X509_REQ_get_attr_by_NID$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle X509_REQ_get_attr_by_NID$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_get_attr_by_NID",
        constants$674.X509_REQ_get_attr_by_NID$FUNC, false
    );
    static final FunctionDescriptor X509_REQ_get_attr_by_OBJ$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_REQ_get_attr_by_OBJ$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_get_attr_by_OBJ",
        constants$674.X509_REQ_get_attr_by_OBJ$FUNC, false
    );
    static final FunctionDescriptor X509_REQ_get_attr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_REQ_get_attr$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_get_attr",
        constants$674.X509_REQ_get_attr$FUNC, false
    );
}

