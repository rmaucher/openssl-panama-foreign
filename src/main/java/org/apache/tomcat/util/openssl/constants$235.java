// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$235 {

    static final FunctionDescriptor a2d_ASN1_OBJECT$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle a2d_ASN1_OBJECT$MH = RuntimeHelper.downcallHandle(
        "a2d_ASN1_OBJECT",
        constants$235.a2d_ASN1_OBJECT$FUNC, false
    );
    static final FunctionDescriptor ASN1_OBJECT_create$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_OBJECT_create$MH = RuntimeHelper.downcallHandle(
        "ASN1_OBJECT_create",
        constants$235.ASN1_OBJECT_create$FUNC, false
    );
    static final FunctionDescriptor ASN1_INTEGER_get_int64$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_INTEGER_get_int64$MH = RuntimeHelper.downcallHandle(
        "ASN1_INTEGER_get_int64",
        constants$235.ASN1_INTEGER_get_int64$FUNC, false
    );
    static final FunctionDescriptor ASN1_INTEGER_set_int64$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_INTEGER_set_int64$MH = RuntimeHelper.downcallHandle(
        "ASN1_INTEGER_set_int64",
        constants$235.ASN1_INTEGER_set_int64$FUNC, false
    );
    static final FunctionDescriptor ASN1_INTEGER_get_uint64$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_INTEGER_get_uint64$MH = RuntimeHelper.downcallHandle(
        "ASN1_INTEGER_get_uint64",
        constants$235.ASN1_INTEGER_get_uint64$FUNC, false
    );
    static final FunctionDescriptor ASN1_INTEGER_set_uint64$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_INTEGER_set_uint64$MH = RuntimeHelper.downcallHandle(
        "ASN1_INTEGER_set_uint64",
        constants$235.ASN1_INTEGER_set_uint64$FUNC, false
    );
}


