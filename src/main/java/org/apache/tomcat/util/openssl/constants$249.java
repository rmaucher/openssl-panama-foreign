// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$249 {

    static final FunctionDescriptor ASN1_PCTX_set_cert_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_PCTX_set_cert_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_set_cert_flags",
        constants$249.ASN1_PCTX_set_cert_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_get_oid_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle ASN1_PCTX_get_oid_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_get_oid_flags",
        constants$249.ASN1_PCTX_get_oid_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_set_oid_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_PCTX_set_oid_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_set_oid_flags",
        constants$249.ASN1_PCTX_set_oid_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_get_str_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle ASN1_PCTX_get_str_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_get_str_flags",
        constants$249.ASN1_PCTX_get_str_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_PCTX_set_str_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle ASN1_PCTX_set_str_flags$MH = RuntimeHelper.downcallHandle(
        "ASN1_PCTX_set_str_flags",
        constants$249.ASN1_PCTX_set_str_flags$FUNC, false
    );
    static final FunctionDescriptor ASN1_SCTX_new$scan_cb$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
}


