// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$1006 {

    static final FunctionDescriptor d2i_AUTHORITY_INFO_ACCESS$FUNC = FunctionDescriptor.of(ADDRESS,
        ADDRESS,
        ADDRESS,
        JAVA_LONG
    );
    static final MethodHandle d2i_AUTHORITY_INFO_ACCESS$MH = RuntimeHelper.downcallHandle(
        "d2i_AUTHORITY_INFO_ACCESS",
        constants$1006.d2i_AUTHORITY_INFO_ACCESS$FUNC, false
    );
    static final FunctionDescriptor i2d_AUTHORITY_INFO_ACCESS$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle i2d_AUTHORITY_INFO_ACCESS$MH = RuntimeHelper.downcallHandle(
        "i2d_AUTHORITY_INFO_ACCESS",
        constants$1006.i2d_AUTHORITY_INFO_ACCESS$FUNC, false
    );
    static final FunctionDescriptor POLICY_MAPPING_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle POLICY_MAPPING_new$MH = RuntimeHelper.downcallHandle(
        "POLICY_MAPPING_new",
        constants$1006.POLICY_MAPPING_new$FUNC, false
    );
    static final FunctionDescriptor POLICY_MAPPING_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle POLICY_MAPPING_free$MH = RuntimeHelper.downcallHandle(
        "POLICY_MAPPING_free",
        constants$1006.POLICY_MAPPING_free$FUNC, false
    );
    static final FunctionDescriptor GENERAL_SUBTREE_new$FUNC = FunctionDescriptor.of(ADDRESS);
    static final MethodHandle GENERAL_SUBTREE_new$MH = RuntimeHelper.downcallHandle(
        "GENERAL_SUBTREE_new",
        constants$1006.GENERAL_SUBTREE_new$FUNC, false
    );
    static final FunctionDescriptor GENERAL_SUBTREE_free$FUNC = FunctionDescriptor.ofVoid(
        ADDRESS
    );
    static final MethodHandle GENERAL_SUBTREE_free$MH = RuntimeHelper.downcallHandle(
        "GENERAL_SUBTREE_free",
        constants$1006.GENERAL_SUBTREE_free$FUNC, false
    );
}


