// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$370 {

    static final FunctionDescriptor EVP_PKEY_meth_get_cleanup$pcleanup$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_cleanup$pcleanup$MH = RuntimeHelper.downcallHandle(
        constants$370.EVP_PKEY_meth_get_cleanup$pcleanup$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_cleanup$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_cleanup$MH = RuntimeHelper.downcallHandle(
        "EVP_PKEY_meth_get_cleanup",
        constants$370.EVP_PKEY_meth_get_cleanup$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_paramgen$pparamgen_init$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_paramgen$pparamgen_init$MH = RuntimeHelper.downcallHandle(
        constants$370.EVP_PKEY_meth_get_paramgen$pparamgen_init$FUNC, false
    );
    static final FunctionDescriptor EVP_PKEY_meth_get_paramgen$pparamgen$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle EVP_PKEY_meth_get_paramgen$pparamgen$MH = RuntimeHelper.downcallHandle(
        constants$370.EVP_PKEY_meth_get_paramgen$pparamgen$FUNC, false
    );
}

