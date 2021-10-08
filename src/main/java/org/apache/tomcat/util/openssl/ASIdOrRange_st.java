// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class ASIdOrRange_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_INT.withName("type"),
        MemoryLayout.paddingLayout(32),
        MemoryLayout.unionLayout(
            ADDRESS.withName("id"),
            ADDRESS.withName("range")
        ).withName("u")
    ).withName("ASIdOrRange_st");
    public static MemoryLayout $LAYOUT() {
        return ASIdOrRange_st.$struct$LAYOUT;
    }
    static final VarHandle type$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("type"));
    public static VarHandle type$VH() {
        return ASIdOrRange_st.type$VH;
    }
    public static int type$get(MemorySegment seg) {
        return (int)ASIdOrRange_st.type$VH.get(seg);
    }
    public static void type$set( MemorySegment seg, int x) {
        ASIdOrRange_st.type$VH.set(seg, x);
    }
    public static int type$get(MemorySegment seg, long index) {
        return (int)ASIdOrRange_st.type$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void type$set(MemorySegment seg, long index, int x) {
        ASIdOrRange_st.type$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static class u {

        static final MemoryLayout u$union$LAYOUT = MemoryLayout.unionLayout(
            ADDRESS.withName("id"),
            ADDRESS.withName("range")
        );
        public static MemoryLayout $LAYOUT() {
            return u.u$union$LAYOUT;
        }
        static final VarHandle id$VH = u$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("id"));
        public static VarHandle id$VH() {
            return u.id$VH;
        }
        public static MemoryAddress id$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)u.id$VH.get(seg);
        }
        public static void id$set( MemorySegment seg, MemoryAddress x) {
            u.id$VH.set(seg, x);
        }
        public static MemoryAddress id$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)u.id$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void id$set(MemorySegment seg, long index, MemoryAddress x) {
            u.id$VH.set(seg.asSlice(index*sizeof()), x);
        }
        static final VarHandle range$VH = u$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("range"));
        public static VarHandle range$VH() {
            return u.range$VH;
        }
        public static MemoryAddress range$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)u.range$VH.get(seg);
        }
        public static void range$set( MemorySegment seg, MemoryAddress x) {
            u.range$VH.set(seg, x);
        }
        public static MemoryAddress range$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)u.range$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void range$set(MemorySegment seg, long index, MemoryAddress x) {
            u.range$VH.set(seg.asSlice(index*sizeof()), x);
        }
        public static long sizeof() { return $LAYOUT().byteSize(); }
        public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
        public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
            return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
        }
        public static MemorySegment allocate(ResourceScope scope) { return allocate(SegmentAllocator.nativeAllocator(scope)); }
        public static MemorySegment allocateArray(int len, ResourceScope scope) {
            return allocateArray(len, SegmentAllocator.nativeAllocator(scope));
        }
        public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
    }

    public static MemorySegment u$slice(MemorySegment seg) {
        return seg.asSlice(8, 8);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment allocate(ResourceScope scope) { return allocate(SegmentAllocator.nativeAllocator(scope)); }
    public static MemorySegment allocateArray(int len, ResourceScope scope) {
        return allocateArray(len, SegmentAllocator.nativeAllocator(scope));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


