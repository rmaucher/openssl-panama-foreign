// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$577 {

    static final FunctionDescriptor X509_LOOKUP_new$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_new$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_new",
        constants$577.X509_LOOKUP_new$FUNC, false
    );
    static final FunctionDescriptor X509_LOOKUP_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_free$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_free",
        constants$577.X509_LOOKUP_free$FUNC, false
    );
    static final FunctionDescriptor X509_LOOKUP_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_init$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_init",
        constants$577.X509_LOOKUP_init$FUNC, false
    );
    static final FunctionDescriptor X509_LOOKUP_by_subject$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_by_subject$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_by_subject",
        constants$577.X509_LOOKUP_by_subject$FUNC, false
    );
    static final FunctionDescriptor X509_LOOKUP_by_issuer_serial$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_by_issuer_serial$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_by_issuer_serial",
        constants$577.X509_LOOKUP_by_issuer_serial$FUNC, false
    );
    static final FunctionDescriptor X509_LOOKUP_by_fingerprint$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_LOOKUP_by_fingerprint$MH = RuntimeHelper.downcallHandle(
        "X509_LOOKUP_by_fingerprint",
        constants$577.X509_LOOKUP_by_fingerprint$FUNC, false
    );
}


