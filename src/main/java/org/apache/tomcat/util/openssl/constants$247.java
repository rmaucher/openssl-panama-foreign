// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$247 {

    static final FunctionDescriptor ASN1_add_stable_module$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle ASN1_add_stable_module$MH = RuntimeHelper.downcallHandle(
        "ASN1_add_stable_module",
        constants$247.ASN1_add_stable_module$FUNC, false
    );
    static final FunctionDescriptor ASN1_generate_nconf$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_generate_nconf$MH = RuntimeHelper.downcallHandle(
        "ASN1_generate_nconf",
        constants$247.ASN1_generate_nconf$FUNC, false
    );
    static final FunctionDescriptor ASN1_generate_v3$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_generate_v3$MH = RuntimeHelper.downcallHandle(
        "ASN1_generate_v3",
        constants$247.ASN1_generate_v3$FUNC, false
    );
    static final FunctionDescriptor ASN1_str2mask$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_str2mask$MH = RuntimeHelper.downcallHandle(
        "ASN1_str2mask",
        constants$247.ASN1_str2mask$FUNC, false
    );
    static final FunctionDescriptor ASN1_item_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASN1_item_print$MH = RuntimeHelper.downcallHandle(
        "ASN1_item_print",
        constants$247.ASN1_item_print$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ASN1_PCTX_new$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_new",
        constants$247.ASN1_PCTX_new$FUNC, false
    );
}

