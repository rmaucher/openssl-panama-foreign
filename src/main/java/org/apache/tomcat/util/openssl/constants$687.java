// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$687 {

    static final FunctionDescriptor X509_NAME_ENTRY_create_by_txt$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_NAME_ENTRY_create_by_txt$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_create_by_txt",
        constants$687.X509_NAME_ENTRY_create_by_txt$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_create_by_NID$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_NAME_ENTRY_create_by_NID$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_create_by_NID",
        constants$687.X509_NAME_ENTRY_create_by_NID$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_add_entry_by_txt$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle X509_NAME_add_entry_by_txt$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_add_entry_by_txt",
        constants$687.X509_NAME_add_entry_by_txt$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_create_by_OBJ$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_NAME_ENTRY_create_by_OBJ$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_create_by_OBJ",
        constants$687.X509_NAME_ENTRY_create_by_OBJ$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_set_object$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_NAME_ENTRY_set_object$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_set_object",
        constants$687.X509_NAME_ENTRY_set_object$FUNC, false
    );
    static final FunctionDescriptor X509_NAME_ENTRY_set_data$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_NAME_ENTRY_set_data$MH = RuntimeHelper.downcallHandle(
        "X509_NAME_ENTRY_set_data",
        constants$687.X509_NAME_ENTRY_set_data$FUNC, false
    );
}

