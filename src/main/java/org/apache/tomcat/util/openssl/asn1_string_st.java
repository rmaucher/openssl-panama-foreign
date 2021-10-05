// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class asn1_string_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_INT.withName("length"),
        JAVA_INT.withName("type"),
        ADDRESS.withName("data"),
        JAVA_LONG.withName("flags")
    ).withName("asn1_string_st");
    public static MemoryLayout $LAYOUT() {
        return asn1_string_st.$struct$LAYOUT;
    }
    static final VarHandle length$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("length"));
    public static VarHandle length$VH() {
        return asn1_string_st.length$VH;
    }
    public static int length$get(MemorySegment seg) {
        return (int)asn1_string_st.length$VH.get(seg);
    }
    public static void length$set( MemorySegment seg, int x) {
        asn1_string_st.length$VH.set(seg, x);
    }
    public static int length$get(MemorySegment seg, long index) {
        return (int)asn1_string_st.length$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void length$set(MemorySegment seg, long index, int x) {
        asn1_string_st.length$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle type$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("type"));
    public static VarHandle type$VH() {
        return asn1_string_st.type$VH;
    }
    public static int type$get(MemorySegment seg) {
        return (int)asn1_string_st.type$VH.get(seg);
    }
    public static void type$set( MemorySegment seg, int x) {
        asn1_string_st.type$VH.set(seg, x);
    }
    public static int type$get(MemorySegment seg, long index) {
        return (int)asn1_string_st.type$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void type$set(MemorySegment seg, long index, int x) {
        asn1_string_st.type$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle data$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("data"));
    public static VarHandle data$VH() {
        return asn1_string_st.data$VH;
    }
    public static MemoryAddress data$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)asn1_string_st.data$VH.get(seg);
    }
    public static void data$set( MemorySegment seg, MemoryAddress x) {
        asn1_string_st.data$VH.set(seg, x);
    }
    public static MemoryAddress data$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)asn1_string_st.data$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void data$set(MemorySegment seg, long index, MemoryAddress x) {
        asn1_string_st.data$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("flags"));
    public static VarHandle flags$VH() {
        return asn1_string_st.flags$VH;
    }
    public static long flags$get(MemorySegment seg) {
        return (long)asn1_string_st.flags$VH.get(seg);
    }
    public static void flags$set( MemorySegment seg, long x) {
        asn1_string_st.flags$VH.set(seg, x);
    }
    public static long flags$get(MemorySegment seg, long index) {
        return (long)asn1_string_st.flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void flags$set(MemorySegment seg, long index, long x) {
        asn1_string_st.flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

