// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1005 {

    static final FunctionDescriptor ACCESS_DESCRIPTION_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle ACCESS_DESCRIPTION_new$MH = RuntimeHelper.downcallHandle(
        "ACCESS_DESCRIPTION_new",
        constants$1005.ACCESS_DESCRIPTION_new$FUNC, false
    );
    static final FunctionDescriptor ACCESS_DESCRIPTION_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle ACCESS_DESCRIPTION_free$MH = RuntimeHelper.downcallHandle(
        "ACCESS_DESCRIPTION_free",
        constants$1005.ACCESS_DESCRIPTION_free$FUNC, false
    );
    static final FunctionDescriptor d2i_ACCESS_DESCRIPTION$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_ACCESS_DESCRIPTION$MH = RuntimeHelper.downcallHandle(
        "d2i_ACCESS_DESCRIPTION",
        constants$1005.d2i_ACCESS_DESCRIPTION$FUNC, false
    );
    static final FunctionDescriptor i2d_ACCESS_DESCRIPTION$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_ACCESS_DESCRIPTION$MH = RuntimeHelper.downcallHandle(
        "i2d_ACCESS_DESCRIPTION",
        constants$1005.i2d_ACCESS_DESCRIPTION$FUNC, false
    );
    static final FunctionDescriptor AUTHORITY_INFO_ACCESS_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle AUTHORITY_INFO_ACCESS_new$MH = RuntimeHelper.downcallHandle(
        "AUTHORITY_INFO_ACCESS_new",
        constants$1005.AUTHORITY_INFO_ACCESS_new$FUNC, false
    );
    static final FunctionDescriptor AUTHORITY_INFO_ACCESS_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle AUTHORITY_INFO_ACCESS_free$MH = RuntimeHelper.downcallHandle(
        "AUTHORITY_INFO_ACCESS_free",
        constants$1005.AUTHORITY_INFO_ACCESS_free$FUNC, false
    );
}

