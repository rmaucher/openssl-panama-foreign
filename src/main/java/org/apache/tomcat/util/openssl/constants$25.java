// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
class constants$25 {

    static final MemoryLayout stdin$LAYOUT = ADDRESS;
    static final VarHandle stdin$VH = constants$25.stdin$LAYOUT.varHandle();
    static final MemorySegment stdin$SEGMENT = RuntimeHelper.lookupGlobalVariable("stdin", constants$25.stdin$LAYOUT);
    static final MemoryLayout stdout$LAYOUT = ADDRESS;
    static final VarHandle stdout$VH = constants$25.stdout$LAYOUT.varHandle();
    static final MemorySegment stdout$SEGMENT = RuntimeHelper.lookupGlobalVariable("stdout", constants$25.stdout$LAYOUT);
    static final MemoryLayout stderr$LAYOUT = ADDRESS;
    static final VarHandle stderr$VH = constants$25.stderr$LAYOUT.varHandle();
    static final MemorySegment stderr$SEGMENT = RuntimeHelper.lookupGlobalVariable("stderr", constants$25.stderr$LAYOUT);
    static final FunctionDescriptor remove$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS
    );
    static final MethodHandle remove$MH = RuntimeHelper.downcallHandle(
        "remove",
        constants$25.remove$FUNC, false
    );
    static final FunctionDescriptor rename$FUNC = FunctionDescriptor.of(JAVA_INT,
        ADDRESS,
        ADDRESS
    );
    static final MethodHandle rename$MH = RuntimeHelper.downcallHandle(
        "rename",
        constants$25.rename$FUNC, false
    );
    static final FunctionDescriptor renameat$FUNC = FunctionDescriptor.of(JAVA_INT,
        JAVA_INT,
        ADDRESS,
        JAVA_INT,
        ADDRESS
    );
    static final MethodHandle renameat$MH = RuntimeHelper.downcallHandle(
        "renameat",
        constants$25.renameat$FUNC, false
    );
}


