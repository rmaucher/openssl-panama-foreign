// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$382 {

    static final FunctionDescriptor EVP_PKEY_meth_get_digest_custom$pdigest_custom$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_digest_custom$pdigest_custom$MH = RuntimeHelper.downcallHandle(
        constants$382.EVP_PKEY_meth_get_digest_custom$pdigest_custom$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_digest_custom$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_digest_custom$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_get_digest_custom",
        constants$382.EVP_PKEY_meth_get_digest_custom$FUNC, false
    );
    static final FunctionDescriptor EVP_add_alg_module$FUNC = FunctionDescriptor.ofVoid();
    static final MethodHandle EVP_add_alg_module$MH = RuntimeHelper.downcallHandle(
        "EVP_add_alg_module",
        constants$382.EVP_add_alg_module$FUNC, false
    );
    static final FunctionDescriptor ERR_load_EC_strings$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_load_EC_strings$MH = RuntimeHelper.downcallHandle(
        "ERR_load_EC_strings",
        constants$382.ERR_load_EC_strings$FUNC, false
    );
    static final FunctionDescriptor EC_GFp_simple_method$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle EC_GFp_simple_method$MH = RuntimeHelper.downcallHandle(
        "EC_GFp_simple_method",
        constants$382.EC_GFp_simple_method$FUNC, false
    );
}


