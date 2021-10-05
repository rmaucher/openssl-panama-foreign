// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class buf_mem_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_LONG.withName("length"),
        ADDRESS.withName("data"),
        JAVA_LONG.withName("max"),
        JAVA_LONG.withName("flags")
    ).withName("buf_mem_st");
    public static MemoryLayout $LAYOUT() {
        return buf_mem_st.$struct$LAYOUT;
    }
    static final VarHandle length$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("length"));
    public static VarHandle length$VH() {
        return buf_mem_st.length$VH;
    }
    public static long length$get(MemorySegment seg) {
        return (long)buf_mem_st.length$VH.get(seg);
    }
    public static void length$set( MemorySegment seg, long x) {
        buf_mem_st.length$VH.set(seg, x);
    }
    public static long length$get(MemorySegment seg, long index) {
        return (long)buf_mem_st.length$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void length$set(MemorySegment seg, long index, long x) {
        buf_mem_st.length$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle data$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("data"));
    public static VarHandle data$VH() {
        return buf_mem_st.data$VH;
    }
    public static MemoryAddress data$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)buf_mem_st.data$VH.get(seg);
    }
    public static void data$set( MemorySegment seg, MemoryAddress x) {
        buf_mem_st.data$VH.set(seg, x);
    }
    public static MemoryAddress data$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)buf_mem_st.data$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void data$set(MemorySegment seg, long index, MemoryAddress x) {
        buf_mem_st.data$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle max$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("max"));
    public static VarHandle max$VH() {
        return buf_mem_st.max$VH;
    }
    public static long max$get(MemorySegment seg) {
        return (long)buf_mem_st.max$VH.get(seg);
    }
    public static void max$set( MemorySegment seg, long x) {
        buf_mem_st.max$VH.set(seg, x);
    }
    public static long max$get(MemorySegment seg, long index) {
        return (long)buf_mem_st.max$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void max$set(MemorySegment seg, long index, long x) {
        buf_mem_st.max$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("flags"));
    public static VarHandle flags$VH() {
        return buf_mem_st.flags$VH;
    }
    public static long flags$get(MemorySegment seg) {
        return (long)buf_mem_st.flags$VH.get(seg);
    }
    public static void flags$set( MemorySegment seg, long x) {
        buf_mem_st.flags$VH.set(seg, x);
    }
    public static long flags$get(MemorySegment seg, long index) {
        return (long)buf_mem_st.flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void flags$set(MemorySegment seg, long index, long x) {
        buf_mem_st.flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

