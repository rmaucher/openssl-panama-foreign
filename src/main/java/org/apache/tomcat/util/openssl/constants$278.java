// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$278 {

    static final FunctionDescriptor EVP_MD_CTX_ctrl$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        JAVA_INT,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_MD_CTX_ctrl$MH = RuntimeHelper.downcallHandle(
        "EVP_MD_CTX_ctrl",
        constants$278.EVP_MD_CTX_ctrl$FUNC, false
    );
    static final FunctionDescriptor EVP_MD_CTX_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EVP_MD_CTX_new$MH = RuntimeHelper.downcallHandle(
        "EVP_MD_CTX_new",
        constants$278.EVP_MD_CTX_new$FUNC, false
    );
    static final FunctionDescriptor EVP_MD_CTX_reset$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_MD_CTX_reset$MH = RuntimeHelper.downcallHandle(
        "EVP_MD_CTX_reset",
        constants$278.EVP_MD_CTX_reset$FUNC, false
    );
    static final FunctionDescriptor EVP_MD_CTX_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle EVP_MD_CTX_free$MH = RuntimeHelper.downcallHandle(
        "EVP_MD_CTX_free",
        constants$278.EVP_MD_CTX_free$FUNC, false
    );
    static final FunctionDescriptor EVP_MD_CTX_copy_ex$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_MD_CTX_copy_ex$MH = RuntimeHelper.downcallHandle(
        "EVP_MD_CTX_copy_ex",
        constants$278.EVP_MD_CTX_copy_ex$FUNC, false
    );
    static final FunctionDescriptor EVP_MD_CTX_set_flags$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle EVP_MD_CTX_set_flags$MH = RuntimeHelper.downcallHandle(
        "EVP_MD_CTX_set_flags",
        constants$278.EVP_MD_CTX_set_flags$FUNC, false
    );
}

