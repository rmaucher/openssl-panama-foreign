// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1054 {

    static final FunctionDescriptor sk_ASN1_STRING_pop$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_pop$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_pop",
        constants$1054.sk_ASN1_STRING_pop$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_shift$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_shift$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_shift",
        constants$1054.sk_ASN1_STRING_shift$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_pop_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_pop_free$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_pop_free",
        constants$1054.sk_ASN1_STRING_pop_free$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_insert$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle sk_ASN1_STRING_insert$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_insert",
        constants$1054.sk_ASN1_STRING_insert$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_set$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_set$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_set",
        constants$1054.sk_ASN1_STRING_set$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_STRING_find$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_STRING_find$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_STRING_find",
        constants$1054.sk_ASN1_STRING_find$FUNC, false
    );
}

