// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class lhash_st_CONF_VALUE {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        MemoryLayout.unionLayout(
            ADDRESS.withName("d1"),
            JAVA_LONG.withName("d2"),
            JAVA_INT.withName("d3")
        ).withName("dummy")
    ).withName("lhash_st_CONF_VALUE");
    public static MemoryLayout $LAYOUT() {
        return lhash_st_CONF_VALUE.$struct$LAYOUT;
    }
    public static class lh_CONF_VALUE_dummy {

        static final MemoryLayout lh_CONF_VALUE_dummy$union$LAYOUT = MemoryLayout.unionLayout(
            ADDRESS.withName("d1"),
            JAVA_LONG.withName("d2"),
            JAVA_INT.withName("d3")
        ).withName("lh_CONF_VALUE_dummy");
        public static MemoryLayout $LAYOUT() {
            return lh_CONF_VALUE_dummy.lh_CONF_VALUE_dummy$union$LAYOUT;
        }
        static final VarHandle d1$VH = lh_CONF_VALUE_dummy$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("d1"));
        public static VarHandle d1$VH() {
            return lh_CONF_VALUE_dummy.d1$VH;
        }
        public static MemoryAddress d1$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)lh_CONF_VALUE_dummy.d1$VH.get(seg);
        }
        public static void d1$set( MemorySegment seg, MemoryAddress x) {
            lh_CONF_VALUE_dummy.d1$VH.set(seg, x);
        }
        public static MemoryAddress d1$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)lh_CONF_VALUE_dummy.d1$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void d1$set(MemorySegment seg, long index, MemoryAddress x) {
            lh_CONF_VALUE_dummy.d1$VH.set(seg.asSlice(index*sizeof()), x);
        }
        static final VarHandle d2$VH = lh_CONF_VALUE_dummy$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("d2"));
        public static VarHandle d2$VH() {
            return lh_CONF_VALUE_dummy.d2$VH;
        }
        public static long d2$get(MemorySegment seg) {
            return (long)lh_CONF_VALUE_dummy.d2$VH.get(seg);
        }
        public static void d2$set( MemorySegment seg, long x) {
            lh_CONF_VALUE_dummy.d2$VH.set(seg, x);
        }
        public static long d2$get(MemorySegment seg, long index) {
            return (long)lh_CONF_VALUE_dummy.d2$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void d2$set(MemorySegment seg, long index, long x) {
            lh_CONF_VALUE_dummy.d2$VH.set(seg.asSlice(index*sizeof()), x);
        }
        static final VarHandle d3$VH = lh_CONF_VALUE_dummy$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("d3"));
        public static VarHandle d3$VH() {
            return lh_CONF_VALUE_dummy.d3$VH;
        }
        public static int d3$get(MemorySegment seg) {
            return (int)lh_CONF_VALUE_dummy.d3$VH.get(seg);
        }
        public static void d3$set( MemorySegment seg, int x) {
            lh_CONF_VALUE_dummy.d3$VH.set(seg, x);
        }
        public static int d3$get(MemorySegment seg, long index) {
            return (int)lh_CONF_VALUE_dummy.d3$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void d3$set(MemorySegment seg, long index, int x) {
            lh_CONF_VALUE_dummy.d3$VH.set(seg.asSlice(index*sizeof()), x);
        }
        public static long sizeof() { return $LAYOUT().byteSize(); }
        public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
        public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
            return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
        }
        public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
    }

    public static MemorySegment dummy$slice(MemorySegment seg) {
        return seg.asSlice(0, 8);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


