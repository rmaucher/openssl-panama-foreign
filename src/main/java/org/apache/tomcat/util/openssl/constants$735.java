// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$735 {

    static final FunctionDescriptor ASYNC_get_wait_ctx$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle ASYNC_get_wait_ctx$MH = RuntimeHelper.downcallHandle(
        "ASYNC_get_wait_ctx",
        constants$735.ASYNC_get_wait_ctx$FUNC, false
    );
    static final FunctionDescriptor ASYNC_block_pause$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle ASYNC_block_pause$MH = RuntimeHelper.downcallHandle(
        "ASYNC_block_pause",
        constants$735.ASYNC_block_pause$FUNC, false
    );
    static final FunctionDescriptor ASYNC_unblock_pause$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle ASYNC_unblock_pause$MH = RuntimeHelper.downcallHandle(
        "ASYNC_unblock_pause",
        constants$735.ASYNC_unblock_pause$FUNC, false
    );
    static final FunctionDescriptor ERR_load_CT_strings$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_load_CT_strings$MH = RuntimeHelper.downcallHandle(
        "ERR_load_CT_strings",
        constants$735.ERR_load_CT_strings$FUNC, false
    );
    static final FunctionDescriptor sk_SCT_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_SCT_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$735.sk_SCT_compfunc$FUNC, false
    );
}


