// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$731 {

    static final FunctionDescriptor HMAC_Update$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle HMAC_Update$MH = RuntimeHelper.downcallHandle(
        "HMAC_Update",
        constants$731.HMAC_Update$FUNC, false
    );
    static final FunctionDescriptor HMAC_Final$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle HMAC_Final$MH = RuntimeHelper.downcallHandle(
        "HMAC_Final",
        constants$731.HMAC_Final$FUNC, false
    );
    static final FunctionDescriptor HMAC$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT,
        ADDRESS,
        JAVA_LONG,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle HMAC$MH = RuntimeHelper.downcallHandle(
        "HMAC",
        constants$731.HMAC$FUNC, false
    );
    static final FunctionDescriptor HMAC_CTX_copy$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle HMAC_CTX_copy$MH = RuntimeHelper.downcallHandle(
        "HMAC_CTX_copy",
        constants$731.HMAC_CTX_copy$FUNC, false
    );
    static final FunctionDescriptor HMAC_CTX_set_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle HMAC_CTX_set_flags$MH = RuntimeHelper.downcallHandle(
        "HMAC_CTX_set_flags",
        constants$731.HMAC_CTX_set_flags$FUNC, false
    );
    static final FunctionDescriptor HMAC_CTX_get_md$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle HMAC_CTX_get_md$MH = RuntimeHelper.downcallHandle(
        "HMAC_CTX_get_md",
        constants$731.HMAC_CTX_get_md$FUNC, false
    );
}


