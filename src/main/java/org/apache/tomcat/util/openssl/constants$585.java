// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$585 {

    static final FunctionDescriptor X509_VERIFY_PARAM_get_flags$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle X509_VERIFY_PARAM_get_flags$MH = RuntimeHelper.downcallHandle(
        "X509_VERIFY_PARAM_get_flags",
        constants$585.X509_VERIFY_PARAM_get_flags$FUNC, false
    );
    static final FunctionDescriptor X509_VERIFY_PARAM_set_purpose$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_VERIFY_PARAM_set_purpose$MH = RuntimeHelper.downcallHandle(
        "X509_VERIFY_PARAM_set_purpose",
        constants$585.X509_VERIFY_PARAM_set_purpose$FUNC, false
    );
    static final FunctionDescriptor X509_VERIFY_PARAM_set_trust$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_VERIFY_PARAM_set_trust$MH = RuntimeHelper.downcallHandle(
        "X509_VERIFY_PARAM_set_trust",
        constants$585.X509_VERIFY_PARAM_set_trust$FUNC, false
    );
    static final FunctionDescriptor X509_VERIFY_PARAM_set_depth$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_VERIFY_PARAM_set_depth$MH = RuntimeHelper.downcallHandle(
        "X509_VERIFY_PARAM_set_depth",
        constants$585.X509_VERIFY_PARAM_set_depth$FUNC, false
    );
    static final FunctionDescriptor X509_VERIFY_PARAM_set_auth_level$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle X509_VERIFY_PARAM_set_auth_level$MH = RuntimeHelper.downcallHandle(
        "X509_VERIFY_PARAM_set_auth_level",
        constants$585.X509_VERIFY_PARAM_set_auth_level$FUNC, false
    );
    static final FunctionDescriptor X509_VERIFY_PARAM_get_time$FUNC = FunctionDescriptor.of(JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle X509_VERIFY_PARAM_get_time$MH = RuntimeHelper.downcallHandle(
        "X509_VERIFY_PARAM_get_time",
        constants$585.X509_VERIFY_PARAM_get_time$FUNC, false
    );
}


