// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$990 {

    static final FunctionDescriptor SXNET_get_id_asc$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SXNET_get_id_asc$MH = RuntimeHelper.downcallHandle(
        "SXNET_get_id_asc",
        constants$990.SXNET_get_id_asc$FUNC, false
    );
    static final FunctionDescriptor SXNET_get_id_ulong$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle SXNET_get_id_ulong$MH = RuntimeHelper.downcallHandle(
        "SXNET_get_id_ulong",
        constants$990.SXNET_get_id_ulong$FUNC, false
    );
    static final FunctionDescriptor SXNET_get_id_INTEGER$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle SXNET_get_id_INTEGER$MH = RuntimeHelper.downcallHandle(
        "SXNET_get_id_INTEGER",
        constants$990.SXNET_get_id_INTEGER$FUNC, false
    );
    static final FunctionDescriptor AUTHORITY_KEYID_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle AUTHORITY_KEYID_new$MH = RuntimeHelper.downcallHandle(
        "AUTHORITY_KEYID_new",
        constants$990.AUTHORITY_KEYID_new$FUNC, false
    );
    static final FunctionDescriptor AUTHORITY_KEYID_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle AUTHORITY_KEYID_free$MH = RuntimeHelper.downcallHandle(
        "AUTHORITY_KEYID_free",
        constants$990.AUTHORITY_KEYID_free$FUNC, false
    );
    static final FunctionDescriptor d2i_AUTHORITY_KEYID$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_AUTHORITY_KEYID$MH = RuntimeHelper.downcallHandle(
        "d2i_AUTHORITY_KEYID",
        constants$990.d2i_AUTHORITY_KEYID$FUNC, false
    );
}

