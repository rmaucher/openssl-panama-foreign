// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class ASRange_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("min"),
        ADDRESS.withName("max")
    ).withName("ASRange_st");
    public static MemoryLayout $LAYOUT() {
        return ASRange_st.$struct$LAYOUT;
    }
    static final VarHandle min$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("min"));
    public static VarHandle min$VH() {
        return ASRange_st.min$VH;
    }
    public static MemoryAddress min$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)ASRange_st.min$VH.get(seg);
    }
    public static void min$set( MemorySegment seg, MemoryAddress x) {
        ASRange_st.min$VH.set(seg, x);
    }
    public static MemoryAddress min$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)ASRange_st.min$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void min$set(MemorySegment seg, long index, MemoryAddress x) {
        ASRange_st.min$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle max$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("max"));
    public static VarHandle max$VH() {
        return ASRange_st.max$VH;
    }
    public static MemoryAddress max$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)ASRange_st.max$VH.get(seg);
    }
    public static void max$set( MemorySegment seg, MemoryAddress x) {
        ASRange_st.max$VH.set(seg, x);
    }
    public static MemoryAddress max$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)ASRange_st.max$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void max$set(MemorySegment seg, long index, MemoryAddress x) {
        ASRange_st.max$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


