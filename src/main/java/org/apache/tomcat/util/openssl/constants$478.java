// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$478 {

    static final FunctionDescriptor SHA1$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SHA1$MH = RuntimeHelper.downcallHandle(
        "SHA1",
        constants$478.SHA1$FUNC, false
    );
    static final FunctionDescriptor SHA1_Transform$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SHA1_Transform$MH = RuntimeHelper.downcallHandle(
        "SHA1_Transform",
        constants$478.SHA1_Transform$FUNC, false
    );
    static final FunctionDescriptor SHA224_Init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle SHA224_Init$MH = RuntimeHelper.downcallHandle(
        "SHA224_Init",
        constants$478.SHA224_Init$FUNC, false
    );
    static final FunctionDescriptor SHA224_Update$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SHA224_Update$MH = RuntimeHelper.downcallHandle(
        "SHA224_Update",
        constants$478.SHA224_Update$FUNC, false
    );
    static final FunctionDescriptor SHA224_Final$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SHA224_Final$MH = RuntimeHelper.downcallHandle(
        "SHA224_Final",
        constants$478.SHA224_Final$FUNC, false
    );
    static final FunctionDescriptor SHA224$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_LONG,
        ADDRESS
    );
    static final MethodHandle SHA224$MH = RuntimeHelper.downcallHandle(
        "SHA224",
        constants$478.SHA224$FUNC, false
    );
}


