// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$245 {

    static final FunctionDescriptor ASN1_mbstring_copy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_LONG
    );
    static final MethodHandle ASN1_mbstring_copy$MH = RuntimeHelper.downcallHandle(
        "ASN1_mbstring_copy",
        constants$245.ASN1_mbstring_copy$FUNC, false
    );
    static final FunctionDescriptor ASN1_mbstring_ncopy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_LONG,
        JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle ASN1_mbstring_ncopy$MH = RuntimeHelper.downcallHandle(
        "ASN1_mbstring_ncopy",
        constants$245.ASN1_mbstring_ncopy$FUNC, false
    );
    static final FunctionDescriptor ASN1_STRING_set_by_NID$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle ASN1_STRING_set_by_NID$MH = RuntimeHelper.downcallHandle(
        "ASN1_STRING_set_by_NID",
        constants$245.ASN1_STRING_set_by_NID$FUNC, false
    );
    static final FunctionDescriptor ASN1_STRING_TABLE_get$FUNC = FunctionDescriptor.of(ADDRESS,
        JAVA_INT
    );
    static final MethodHandle ASN1_STRING_TABLE_get$MH = RuntimeHelper.downcallHandle(
        "ASN1_STRING_TABLE_get",
        constants$245.ASN1_STRING_TABLE_get$FUNC, false
    );
    static final FunctionDescriptor ASN1_STRING_TABLE_add$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        JAVA_LONG,
        JAVA_LONG,
        JAVA_LONG,
        JAVA_LONG
    );
    static final MethodHandle ASN1_STRING_TABLE_add$MH = RuntimeHelper.downcallHandle(
        "ASN1_STRING_TABLE_add",
        constants$245.ASN1_STRING_TABLE_add$FUNC, false
    );
    static final FunctionDescriptor ASN1_STRING_TABLE_cleanup$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle ASN1_STRING_TABLE_cleanup$MH = RuntimeHelper.downcallHandle(
        "ASN1_STRING_TABLE_cleanup",
        constants$245.ASN1_STRING_TABLE_cleanup$FUNC, false
    );
}


