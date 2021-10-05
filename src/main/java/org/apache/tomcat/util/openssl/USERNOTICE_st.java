// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class USERNOTICE_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("noticeref"),
        ADDRESS.withName("exptext")
    ).withName("USERNOTICE_st");
    public static MemoryLayout $LAYOUT() {
        return USERNOTICE_st.$struct$LAYOUT;
    }
    static final VarHandle noticeref$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("noticeref"));
    public static VarHandle noticeref$VH() {
        return USERNOTICE_st.noticeref$VH;
    }
    public static MemoryAddress noticeref$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)USERNOTICE_st.noticeref$VH.get(seg);
    }
    public static void noticeref$set( MemorySegment seg, MemoryAddress x) {
        USERNOTICE_st.noticeref$VH.set(seg, x);
    }
    public static MemoryAddress noticeref$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)USERNOTICE_st.noticeref$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void noticeref$set(MemorySegment seg, long index, MemoryAddress x) {
        USERNOTICE_st.noticeref$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle exptext$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("exptext"));
    public static VarHandle exptext$VH() {
        return USERNOTICE_st.exptext$VH;
    }
    public static MemoryAddress exptext$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)USERNOTICE_st.exptext$VH.get(seg);
    }
    public static void exptext$set( MemorySegment seg, MemoryAddress x) {
        USERNOTICE_st.exptext$VH.set(seg, x);
    }
    public static MemoryAddress exptext$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)USERNOTICE_st.exptext$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void exptext$set(MemorySegment seg, long index, MemoryAddress x) {
        USERNOTICE_st.exptext$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


