// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$201 {

    static final FunctionDescriptor sk_ASN1_TYPE_value$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASN1_TYPE_value$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_value",
        constants$201.sk_ASN1_TYPE_value$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_TYPE_new$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_new",
        constants$201.sk_ASN1_TYPE_new$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_new_null$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle sk_ASN1_TYPE_new_null$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_new_null",
        constants$201.sk_ASN1_TYPE_new_null$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_new_reserve$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASN1_TYPE_new_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_new_reserve",
        constants$201.sk_ASN1_TYPE_new_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_reserve$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASN1_TYPE_reserve$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_reserve",
        constants$201.sk_ASN1_TYPE_reserve$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ASN1_TYPE_free$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_free",
        constants$201.sk_ASN1_TYPE_free$FUNC, false
    );
}


