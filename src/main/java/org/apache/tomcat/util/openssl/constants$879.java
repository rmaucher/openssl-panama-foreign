// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$879 {

    static final FunctionDescriptor ERR_set_mark$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_set_mark$MH = RuntimeHelper.downcallHandle(
        "ERR_set_mark",
        constants$879.ERR_set_mark$FUNC, false
    );
    static final FunctionDescriptor ERR_pop_to_mark$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_pop_to_mark$MH = RuntimeHelper.downcallHandle(
        "ERR_pop_to_mark",
        constants$879.ERR_pop_to_mark$FUNC, false
    );
    static final FunctionDescriptor ERR_clear_last_mark$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_clear_last_mark$MH = RuntimeHelper.downcallHandle(
        "ERR_clear_last_mark",
        constants$879.ERR_clear_last_mark$FUNC, false
    );
    static final FunctionDescriptor ERR_load_PKCS12_strings$FUNC = FunctionDescriptor.of(JAVA_INT);
    static final MethodHandle ERR_load_PKCS12_strings$MH = RuntimeHelper.downcallHandle(
        "ERR_load_PKCS12_strings",
        constants$879.ERR_load_PKCS12_strings$FUNC, false
    );
    static final FunctionDescriptor sk_PKCS12_SAFEBAG_compfunc$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle sk_PKCS12_SAFEBAG_compfunc$MH = RuntimeHelper.downcallHandle(
        constants$879.sk_PKCS12_SAFEBAG_compfunc$FUNC, false
    );
}


