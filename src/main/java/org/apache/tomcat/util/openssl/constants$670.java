// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$670 {

    static final FunctionDescriptor X509_get0_extensions$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_get0_extensions$MH = RuntimeHelper.downcallHandle(
        "X509_get0_extensions",
        constants$670.X509_get0_extensions$FUNC, false
    );
    static final FunctionDescriptor X509_get0_uids$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_get0_uids$MH = RuntimeHelper.downcallHandle(
        "X509_get0_uids",
        constants$670.X509_get0_uids$FUNC, false
    );
    static final FunctionDescriptor X509_get0_tbs_sigalg$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_get0_tbs_sigalg$MH = RuntimeHelper.downcallHandle(
        "X509_get0_tbs_sigalg",
        constants$670.X509_get0_tbs_sigalg$FUNC, false
    );
    static final FunctionDescriptor X509_get0_pubkey$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_get0_pubkey$MH = RuntimeHelper.downcallHandle(
        "X509_get0_pubkey",
        constants$670.X509_get0_pubkey$FUNC, false
    );
    static final FunctionDescriptor X509_get_pubkey$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_get_pubkey$MH = RuntimeHelper.downcallHandle(
        "X509_get_pubkey",
        constants$670.X509_get_pubkey$FUNC, false
    );
    static final FunctionDescriptor X509_get0_pubkey_bitstr$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_get0_pubkey_bitstr$MH = RuntimeHelper.downcallHandle(
        "X509_get0_pubkey_bitstr",
        constants$670.X509_get0_pubkey_bitstr$FUNC, false
    );
}

