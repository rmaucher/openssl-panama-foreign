// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$181 {

    static final FunctionDescriptor sk_ASN1_STRING_TABLE_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASN1_STRING_TABLE_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_TABLE_reserve",
        constants$181.sk_ASN1_STRING_TABLE_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_TABLE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_TABLE_free$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_TABLE_free",
        constants$181.sk_ASN1_STRING_TABLE_free$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_TABLE_zero$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_TABLE_zero$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_TABLE_zero",
        constants$181.sk_ASN1_STRING_TABLE_zero$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_TABLE_delete$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASN1_STRING_TABLE_delete$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_TABLE_delete",
        constants$181.sk_ASN1_STRING_TABLE_delete$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_TABLE_delete_ptr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_TABLE_delete_ptr$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_TABLE_delete_ptr",
        constants$181.sk_ASN1_STRING_TABLE_delete_ptr$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_TABLE_push$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_TABLE_push$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_TABLE_push",
        constants$181.sk_ASN1_STRING_TABLE_push$FUNC, false
    );
}


