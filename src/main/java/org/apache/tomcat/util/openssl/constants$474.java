// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$474 {

    static final FunctionDescriptor DSA_meth_set_mod_exp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_meth_set_mod_exp$MH = RuntimeHelper.downcallHandle(
        "DSA_meth_set_mod_exp",
        constants$474.DSA_meth_set_mod_exp$FUNC, false
    );
    static final FunctionDescriptor DSA_meth_get_bn_mod_exp$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_meth_get_bn_mod_exp$MH = RuntimeHelper.downcallHandle(
        "DSA_meth_get_bn_mod_exp",
        constants$474.DSA_meth_get_bn_mod_exp$FUNC, false
    );
    static final FunctionDescriptor DSA_meth_set_bn_mod_exp$bn_mod_exp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_meth_set_bn_mod_exp$bn_mod_exp$MH = RuntimeHelper.downcallHandle(
        constants$474.DSA_meth_set_bn_mod_exp$bn_mod_exp$FUNC, false
    );
    static final FunctionDescriptor DSA_meth_set_bn_mod_exp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_meth_set_bn_mod_exp$MH = RuntimeHelper.downcallHandle(
        "DSA_meth_set_bn_mod_exp",
        constants$474.DSA_meth_set_bn_mod_exp$FUNC, false
    );
    static final FunctionDescriptor DSA_meth_get_init$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_meth_get_init$MH = RuntimeHelper.downcallHandle(
        "DSA_meth_get_init",
        constants$474.DSA_meth_get_init$FUNC, false
    );
}


