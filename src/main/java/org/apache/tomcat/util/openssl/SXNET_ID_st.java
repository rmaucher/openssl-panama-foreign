// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class SXNET_ID_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("zone"),
        ADDRESS.withName("user")
    ).withName("SXNET_ID_st");
    public static MemoryLayout $LAYOUT() {
        return SXNET_ID_st.$struct$LAYOUT;
    }
    static final VarHandle zone$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("zone"));
    public static VarHandle zone$VH() {
        return SXNET_ID_st.zone$VH;
    }
    public static MemoryAddress zone$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)SXNET_ID_st.zone$VH.get(seg);
    }
    public static void zone$set( MemorySegment seg, MemoryAddress x) {
        SXNET_ID_st.zone$VH.set(seg, x);
    }
    public static MemoryAddress zone$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)SXNET_ID_st.zone$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void zone$set(MemorySegment seg, long index, MemoryAddress x) {
        SXNET_ID_st.zone$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle user$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("user"));
    public static VarHandle user$VH() {
        return SXNET_ID_st.user$VH;
    }
    public static MemoryAddress user$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)SXNET_ID_st.user$VH.get(seg);
    }
    public static void user$set( MemorySegment seg, MemoryAddress x) {
        SXNET_ID_st.user$VH.set(seg, x);
    }
    public static MemoryAddress user$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)SXNET_ID_st.user$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void user$set(MemorySegment seg, long index, MemoryAddress x) {
        SXNET_ID_st.user$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

