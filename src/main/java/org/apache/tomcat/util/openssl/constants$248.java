// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$248 {

    static final FunctionDescriptor ASN1_PCTX_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ASN1_PCTX_free$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_free",
        constants$248.ASN1_PCTX_free$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_get_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle ASN1_PCTX_get_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_get_flags",
        constants$248.ASN1_PCTX_get_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_set_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_PCTX_set_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_set_flags",
        constants$248.ASN1_PCTX_set_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_get_nm_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle ASN1_PCTX_get_nm_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_get_nm_flags",
        constants$248.ASN1_PCTX_get_nm_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_set_nm_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_PCTX_set_nm_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_set_nm_flags",
        constants$248.ASN1_PCTX_set_nm_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_get_cert_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle ASN1_PCTX_get_cert_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_get_cert_flags",
        constants$248.ASN1_PCTX_get_cert_flags$FUNC, false
    );
}


