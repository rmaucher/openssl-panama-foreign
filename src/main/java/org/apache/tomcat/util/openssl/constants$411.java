// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$411 {

    static final FunctionDescriptor EC_KEY_METHOD_set_init$set_group$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_METHOD_set_init$set_group$MH = RuntimeHelper.downcallHandle(
        constants$411.EC_KEY_METHOD_set_init$set_group$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_METHOD_set_init$set_private$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_METHOD_set_init$set_private$MH = RuntimeHelper.downcallHandle(
        constants$411.EC_KEY_METHOD_set_init$set_private$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_METHOD_set_init$set_public$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_METHOD_set_init$set_public$MH = RuntimeHelper.downcallHandle(
        constants$411.EC_KEY_METHOD_set_init$set_public$FUNC, false
    );
    static final FunctionDescriptor EC_KEY_METHOD_set_init$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EC_KEY_METHOD_set_init$MH = RuntimeHelper.downcallHandle(
        "EC_KEY_METHOD_set_init",
        constants$411.EC_KEY_METHOD_set_init$FUNC, false
    );
}

