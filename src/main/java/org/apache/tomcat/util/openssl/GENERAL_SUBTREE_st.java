// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class GENERAL_SUBTREE_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("base"),
        ADDRESS.withName("minimum"),
        ADDRESS.withName("maximum")
    ).withName("GENERAL_SUBTREE_st");
    public static MemoryLayout $LAYOUT() {
        return GENERAL_SUBTREE_st.$struct$LAYOUT;
    }
    static final VarHandle base$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("base"));
    public static VarHandle base$VH() {
        return GENERAL_SUBTREE_st.base$VH;
    }
    public static MemoryAddress base$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)GENERAL_SUBTREE_st.base$VH.get(seg);
    }
    public static void base$set( MemorySegment seg, MemoryAddress x) {
        GENERAL_SUBTREE_st.base$VH.set(seg, x);
    }
    public static MemoryAddress base$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)GENERAL_SUBTREE_st.base$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void base$set(MemorySegment seg, long index, MemoryAddress x) {
        GENERAL_SUBTREE_st.base$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle minimum$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("minimum"));
    public static VarHandle minimum$VH() {
        return GENERAL_SUBTREE_st.minimum$VH;
    }
    public static MemoryAddress minimum$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)GENERAL_SUBTREE_st.minimum$VH.get(seg);
    }
    public static void minimum$set( MemorySegment seg, MemoryAddress x) {
        GENERAL_SUBTREE_st.minimum$VH.set(seg, x);
    }
    public static MemoryAddress minimum$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)GENERAL_SUBTREE_st.minimum$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void minimum$set(MemorySegment seg, long index, MemoryAddress x) {
        GENERAL_SUBTREE_st.minimum$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle maximum$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("maximum"));
    public static VarHandle maximum$VH() {
        return GENERAL_SUBTREE_st.maximum$VH;
    }
    public static MemoryAddress maximum$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)GENERAL_SUBTREE_st.maximum$VH.get(seg);
    }
    public static void maximum$set( MemorySegment seg, MemoryAddress x) {
        GENERAL_SUBTREE_st.maximum$VH.set(seg, x);
    }
    public static MemoryAddress maximum$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)GENERAL_SUBTREE_st.maximum$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void maximum$set(MemorySegment seg, long index, MemoryAddress x) {
        GENERAL_SUBTREE_st.maximum$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

