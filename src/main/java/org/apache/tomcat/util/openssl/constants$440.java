// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$440 {

    static final FunctionDescriptor RSA_meth_get_priv_dec$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_meth_get_priv_dec$MH = RuntimeHelper.downcallHandle(
        "RSA_meth_get_priv_dec",
        constants$440.RSA_meth_get_priv_dec$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_set_priv_dec$priv_dec$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle RSA_meth_set_priv_dec$priv_dec$MH = RuntimeHelper.downcallHandle(
        constants$440.RSA_meth_set_priv_dec$priv_dec$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_set_priv_dec$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_meth_set_priv_dec$MH = RuntimeHelper.downcallHandle(
        "RSA_meth_set_priv_dec",
        constants$440.RSA_meth_set_priv_dec$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_get_mod_exp$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle RSA_meth_get_mod_exp$MH = RuntimeHelper.downcallHandle(
        "RSA_meth_get_mod_exp",
        constants$440.RSA_meth_get_mod_exp$FUNC, false
    );
    static final FunctionDescriptor RSA_meth_set_mod_exp$mod_exp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
}


