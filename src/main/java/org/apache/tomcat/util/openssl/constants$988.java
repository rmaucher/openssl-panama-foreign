// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$988 {

    static final FunctionDescriptor i2d_BASIC_CONSTRAINTS$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_BASIC_CONSTRAINTS$MH = RuntimeHelper.downcallHandle(
        "i2d_BASIC_CONSTRAINTS",
        constants$988.i2d_BASIC_CONSTRAINTS$FUNC, false
    );
    static final FunctionDescriptor SXNET_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle SXNET_new$MH = RuntimeHelper.downcallHandle(
        "SXNET_new",
        constants$988.SXNET_new$FUNC, false
    );
    static final FunctionDescriptor SXNET_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle SXNET_free$MH = RuntimeHelper.downcallHandle(
        "SXNET_free",
        constants$988.SXNET_free$FUNC, false
    );
    static final FunctionDescriptor d2i_SXNET$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_SXNET$MH = RuntimeHelper.downcallHandle(
        "d2i_SXNET",
        constants$988.d2i_SXNET$FUNC, false
    );
    static final FunctionDescriptor i2d_SXNET$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_SXNET$MH = RuntimeHelper.downcallHandle(
        "i2d_SXNET",
        constants$988.i2d_SXNET$FUNC, false
    );
    static final FunctionDescriptor SXNETID_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle SXNETID_new$MH = RuntimeHelper.downcallHandle(
        "SXNETID_new",
        constants$988.SXNETID_new$FUNC, false
    );
}


