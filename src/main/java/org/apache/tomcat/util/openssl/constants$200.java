// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$200 {

    static final FunctionDescriptor sk_ASN1_TYPE_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_TYPE_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$200.sk_ASN1_TYPE_compfunc$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_freefunc$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle sk_ASN1_TYPE_freefunc$MH = RuntimeHelper.downcallHandle(
        constants$200.sk_ASN1_TYPE_freefunc$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_copyfunc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_TYPE_copyfunc$MH = RuntimeHelper.downcallHandle(
        constants$200.sk_ASN1_TYPE_copyfunc$FUNC, false
    );
    static final FunctionDescriptor sk_ASN1_TYPE_num$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle sk_ASN1_TYPE_num$MH = RuntimeHelper.downcallHandle(
        "sk_ASN1_TYPE_num",
        constants$200.sk_ASN1_TYPE_num$FUNC, false
    );
}

