// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$467 {

    static final FunctionDescriptor DSAparams_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSAparams_print$MH = RuntimeHelper.downcallHandle(
        "DSAparams_print",
        constants$467.DSAparams_print$FUNC, false
    );
    static final FunctionDescriptor DSA_print$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle DSA_print$MH = RuntimeHelper.downcallHandle(
        "DSA_print",
        constants$467.DSA_print$FUNC, false
    );
    static final FunctionDescriptor DSAparams_print_fp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSAparams_print_fp$MH = RuntimeHelper.downcallHandle(
        "DSAparams_print_fp",
        constants$467.DSAparams_print_fp$FUNC, false
    );
    static final FunctionDescriptor DSA_print_fp$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS,
        JAVA_INT
    );
    static final MethodHandle DSA_print_fp$MH = RuntimeHelper.downcallHandle(
        "DSA_print_fp",
        constants$467.DSA_print_fp$FUNC, false
    );
    static final FunctionDescriptor DSA_dup_DH$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_dup_DH$MH = RuntimeHelper.downcallHandle(
        "DSA_dup_DH",
        constants$467.DSA_dup_DH$FUNC, false
    );
    static final FunctionDescriptor DSA_get0_pqg$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS,
        ADDRESS,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle DSA_get0_pqg$MH = RuntimeHelper.downcallHandle(
        "DSA_get0_pqg",
        constants$467.DSA_get0_pqg$FUNC, false
    );
}


