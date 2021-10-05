// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class SHAstate_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_INT.withName("h0"),
        JAVA_INT.withName("h1"),
        JAVA_INT.withName("h2"),
        JAVA_INT.withName("h3"),
        JAVA_INT.withName("h4"),
        JAVA_INT.withName("Nl"),
        JAVA_INT.withName("Nh"),
        MemoryLayout.sequenceLayout(16, JAVA_INT).withName("data"),
        JAVA_INT.withName("num")
    ).withName("SHAstate_st");
    public static MemoryLayout $LAYOUT() {
        return SHAstate_st.$struct$LAYOUT;
    }
    static final VarHandle h0$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("h0"));
    public static VarHandle h0$VH() {
        return SHAstate_st.h0$VH;
    }
    public static int h0$get(MemorySegment seg) {
        return (int)SHAstate_st.h0$VH.get(seg);
    }
    public static void h0$set( MemorySegment seg, int x) {
        SHAstate_st.h0$VH.set(seg, x);
    }
    public static int h0$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.h0$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void h0$set(MemorySegment seg, long index, int x) {
        SHAstate_st.h0$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle h1$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("h1"));
    public static VarHandle h1$VH() {
        return SHAstate_st.h1$VH;
    }
    public static int h1$get(MemorySegment seg) {
        return (int)SHAstate_st.h1$VH.get(seg);
    }
    public static void h1$set( MemorySegment seg, int x) {
        SHAstate_st.h1$VH.set(seg, x);
    }
    public static int h1$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.h1$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void h1$set(MemorySegment seg, long index, int x) {
        SHAstate_st.h1$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle h2$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("h2"));
    public static VarHandle h2$VH() {
        return SHAstate_st.h2$VH;
    }
    public static int h2$get(MemorySegment seg) {
        return (int)SHAstate_st.h2$VH.get(seg);
    }
    public static void h2$set( MemorySegment seg, int x) {
        SHAstate_st.h2$VH.set(seg, x);
    }
    public static int h2$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.h2$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void h2$set(MemorySegment seg, long index, int x) {
        SHAstate_st.h2$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle h3$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("h3"));
    public static VarHandle h3$VH() {
        return SHAstate_st.h3$VH;
    }
    public static int h3$get(MemorySegment seg) {
        return (int)SHAstate_st.h3$VH.get(seg);
    }
    public static void h3$set( MemorySegment seg, int x) {
        SHAstate_st.h3$VH.set(seg, x);
    }
    public static int h3$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.h3$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void h3$set(MemorySegment seg, long index, int x) {
        SHAstate_st.h3$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle h4$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("h4"));
    public static VarHandle h4$VH() {
        return SHAstate_st.h4$VH;
    }
    public static int h4$get(MemorySegment seg) {
        return (int)SHAstate_st.h4$VH.get(seg);
    }
    public static void h4$set( MemorySegment seg, int x) {
        SHAstate_st.h4$VH.set(seg, x);
    }
    public static int h4$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.h4$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void h4$set(MemorySegment seg, long index, int x) {
        SHAstate_st.h4$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle Nl$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Nl"));
    public static VarHandle Nl$VH() {
        return SHAstate_st.Nl$VH;
    }
    public static int Nl$get(MemorySegment seg) {
        return (int)SHAstate_st.Nl$VH.get(seg);
    }
    public static void Nl$set( MemorySegment seg, int x) {
        SHAstate_st.Nl$VH.set(seg, x);
    }
    public static int Nl$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.Nl$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void Nl$set(MemorySegment seg, long index, int x) {
        SHAstate_st.Nl$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle Nh$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Nh"));
    public static VarHandle Nh$VH() {
        return SHAstate_st.Nh$VH;
    }
    public static int Nh$get(MemorySegment seg) {
        return (int)SHAstate_st.Nh$VH.get(seg);
    }
    public static void Nh$set( MemorySegment seg, int x) {
        SHAstate_st.Nh$VH.set(seg, x);
    }
    public static int Nh$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.Nh$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void Nh$set(MemorySegment seg, long index, int x) {
        SHAstate_st.Nh$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static MemorySegment data$slice(MemorySegment seg) {
        return seg.asSlice(28, 64);
    }
    static final VarHandle num$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("num"));
    public static VarHandle num$VH() {
        return SHAstate_st.num$VH;
    }
    public static int num$get(MemorySegment seg) {
        return (int)SHAstate_st.num$VH.get(seg);
    }
    public static void num$set( MemorySegment seg, int x) {
        SHAstate_st.num$VH.set(seg, x);
    }
    public static int num$get(MemorySegment seg, long index) {
        return (int)SHAstate_st.num$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void num$set(MemorySegment seg, long index, int x) {
        SHAstate_st.num$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


