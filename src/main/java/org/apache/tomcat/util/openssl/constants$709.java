// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$709 {

    static final FunctionDescriptor PEM_do_header$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_do_header$MH = RuntimeHelper.downcallHandle(
        "PEM_do_header",
        constants$709.PEM_do_header$FUNC, false
    );
    static final FunctionDescriptor PEM_read_bio$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_read_bio$MH = RuntimeHelper.downcallHandle(
        "PEM_read_bio",
        constants$709.PEM_read_bio$FUNC, false
    );
    static final FunctionDescriptor PEM_read_bio_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle PEM_read_bio_ex$MH = RuntimeHelper.downcallHandle(
        "PEM_read_bio_ex",
        constants$709.PEM_read_bio_ex$FUNC, false
    );
    static final FunctionDescriptor PEM_bytes_read_bio_secmem$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_bytes_read_bio_secmem$MH = RuntimeHelper.downcallHandle(
        "PEM_bytes_read_bio_secmem",
        constants$709.PEM_bytes_read_bio_secmem$FUNC, false
    );
    static final FunctionDescriptor PEM_write_bio$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle PEM_write_bio$MH = RuntimeHelper.downcallHandle(
        "PEM_write_bio",
        constants$709.PEM_write_bio$FUNC, false
    );
    static final FunctionDescriptor PEM_bytes_read_bio$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle PEM_bytes_read_bio$MH = RuntimeHelper.downcallHandle(
        "PEM_bytes_read_bio",
        constants$709.PEM_bytes_read_bio$FUNC, false
    );
}


