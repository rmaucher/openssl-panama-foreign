// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$643 {

    static final FunctionDescriptor X509_get_default_cert_file$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_get_default_cert_file$MH = RuntimeHelper.downcallHandle(
        "X509_get_default_cert_file",
        constants$643.X509_get_default_cert_file$FUNC, false
    );
    static final FunctionDescriptor X509_get_default_cert_dir_env$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_get_default_cert_dir_env$MH = RuntimeHelper.downcallHandle(
        "X509_get_default_cert_dir_env",
        constants$643.X509_get_default_cert_dir_env$FUNC, false
    );
    static final FunctionDescriptor X509_get_default_cert_file_env$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_get_default_cert_file_env$MH = RuntimeHelper.downcallHandle(
        "X509_get_default_cert_file_env",
        constants$643.X509_get_default_cert_file_env$FUNC, false
    );
    static final FunctionDescriptor X509_get_default_private_dir$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle X509_get_default_private_dir$MH = RuntimeHelper.downcallHandle(
        "X509_get_default_private_dir",
        constants$643.X509_get_default_private_dir$FUNC, false
    );
    static final FunctionDescriptor X509_to_X509_REQ$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle X509_to_X509_REQ$MH = RuntimeHelper.downcallHandle(
        "X509_to_X509_REQ",
        constants$643.X509_to_X509_REQ$FUNC, false
    );
    static final FunctionDescriptor X509_REQ_to_X509$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_REQ_to_X509$MH = RuntimeHelper.downcallHandle(
        "X509_REQ_to_X509",
        constants$643.X509_REQ_to_X509$FUNC, false
    );
}

