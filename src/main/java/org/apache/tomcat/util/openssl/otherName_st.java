// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class otherName_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("type_id"),
        ADDRESS.withName("value")
    ).withName("otherName_st");
    public static MemoryLayout $LAYOUT() {
        return otherName_st.$struct$LAYOUT;
    }
    static final VarHandle type_id$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("type_id"));
    public static VarHandle type_id$VH() {
        return otherName_st.type_id$VH;
    }
    public static MemoryAddress type_id$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)otherName_st.type_id$VH.get(seg);
    }
    public static void type_id$set( MemorySegment seg, MemoryAddress x) {
        otherName_st.type_id$VH.set(seg, x);
    }
    public static MemoryAddress type_id$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)otherName_st.type_id$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void type_id$set(MemorySegment seg, long index, MemoryAddress x) {
        otherName_st.type_id$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle value$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("value"));
    public static VarHandle value$VH() {
        return otherName_st.value$VH;
    }
    public static MemoryAddress value$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)otherName_st.value$VH.get(seg);
    }
    public static void value$set( MemorySegment seg, MemoryAddress x) {
        otherName_st.value$VH.set(seg, x);
    }
    public static MemoryAddress value$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)otherName_st.value$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void value$set(MemorySegment seg, long index, MemoryAddress x) {
        otherName_st.value$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


