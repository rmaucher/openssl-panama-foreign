// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1015 {

    static final FunctionDescriptor X509V3_add1_i2d$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_LONG
    );
    static final MethodHandle X509V3_add1_i2d$MH = RuntimeHelper.downcallHandle(
        "X509V3_add1_i2d",
        constants$1015.X509V3_add1_i2d$FUNC, false
    );
    static final FunctionDescriptor X509V3_EXT_val_prn$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle X509V3_EXT_val_prn$MH = RuntimeHelper.downcallHandle(
        "X509V3_EXT_val_prn",
        constants$1015.X509V3_EXT_val_prn$FUNC, false
    );
    static final FunctionDescriptor X509V3_EXT_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        JAVA_INT
    );
    static final MethodHandle X509V3_EXT_print$MH = RuntimeHelper.downcallHandle(
        "X509V3_EXT_print",
        constants$1015.X509V3_EXT_print$FUNC, false
    );
    static final FunctionDescriptor X509V3_EXT_print_fp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        JAVA_INT
    );
    static final MethodHandle X509V3_EXT_print_fp$MH = RuntimeHelper.downcallHandle(
        "X509V3_EXT_print_fp",
        constants$1015.X509V3_EXT_print_fp$FUNC, false
    );
    static final FunctionDescriptor X509V3_extensions_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG,
        JAVA_INT
    );
    static final MethodHandle X509V3_extensions_print$MH = RuntimeHelper.downcallHandle(
        "X509V3_extensions_print",
        constants$1015.X509V3_extensions_print$FUNC, false
    );
    static final FunctionDescriptor X509_check_ca$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle X509_check_ca$MH = RuntimeHelper.downcallHandle(
        "X509_check_ca",
        constants$1015.X509_check_ca$FUNC, false
    );
}

