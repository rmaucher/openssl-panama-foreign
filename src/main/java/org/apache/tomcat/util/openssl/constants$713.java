// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$713 {

    static final FunctionDescriptor PEM_write_X509$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_write_X509$MH = RuntimeHelper.downcallHandle(
        "PEM_write_X509",
        constants$713.PEM_write_X509$FUNC, false
    );
    static final FunctionDescriptor PEM_read_bio_X509_AUX$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_read_bio_X509_AUX$MH = RuntimeHelper.downcallHandle(
        "PEM_read_bio_X509_AUX",
        constants$713.PEM_read_bio_X509_AUX$FUNC, false
    );
    static final FunctionDescriptor PEM_read_X509_AUX$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_read_X509_AUX$MH = RuntimeHelper.downcallHandle(
        "PEM_read_X509_AUX",
        constants$713.PEM_read_X509_AUX$FUNC, false
    );
    static final FunctionDescriptor PEM_write_bio_X509_AUX$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_write_bio_X509_AUX$MH = RuntimeHelper.downcallHandle(
        "PEM_write_bio_X509_AUX",
        constants$713.PEM_write_bio_X509_AUX$FUNC, false
    );
    static final FunctionDescriptor PEM_write_X509_AUX$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_write_X509_AUX$MH = RuntimeHelper.downcallHandle(
        "PEM_write_X509_AUX",
        constants$713.PEM_write_X509_AUX$FUNC, false
    );
    static final FunctionDescriptor PEM_read_bio_X509_REQ$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_read_bio_X509_REQ$MH = RuntimeHelper.downcallHandle(
        "PEM_read_bio_X509_REQ",
        constants$713.PEM_read_bio_X509_REQ$FUNC, false
    );
}

