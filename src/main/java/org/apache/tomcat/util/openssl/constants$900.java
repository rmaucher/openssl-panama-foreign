// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$900 {

    static final FunctionDescriptor RAND_add$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT,
        JAVA_DOUBLE
    );
    static final MethodHandle RAND_add$MH = RuntimeHelper.downcallHandle(
        "RAND_add",
        constants$900.RAND_add$FUNC, false
    );
    static final FunctionDescriptor RAND_load_file$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle RAND_load_file$MH = RuntimeHelper.downcallHandle(
        "RAND_load_file",
        constants$900.RAND_load_file$FUNC, false
    );
    static final FunctionDescriptor RAND_write_file$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle RAND_write_file$MH = RuntimeHelper.downcallHandle(
        "RAND_write_file",
        constants$900.RAND_write_file$FUNC, false
    );
    static final FunctionDescriptor RAND_file_name$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle RAND_file_name$MH = RuntimeHelper.downcallHandle(
        "RAND_file_name",
        constants$900.RAND_file_name$FUNC, false
    );
    static final FunctionDescriptor RAND_status$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle RAND_status$MH = RuntimeHelper.downcallHandle(
        "RAND_status",
        constants$900.RAND_status$FUNC, false
    );
    static final FunctionDescriptor RAND_poll$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle RAND_poll$MH = RuntimeHelper.downcallHandle(
        "RAND_poll",
        constants$900.RAND_poll$FUNC, false
    );
}

