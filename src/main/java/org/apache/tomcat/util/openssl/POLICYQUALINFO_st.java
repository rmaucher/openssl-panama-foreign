// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class POLICYQUALINFO_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        ADDRESS.withName("pqualid"),
        MemoryLayout.unionLayout(
            ADDRESS.withName("cpsuri"),
            ADDRESS.withName("usernotice"),
            ADDRESS.withName("other")
        ).withName("d")
    ).withName("POLICYQUALINFO_st");
    public static MemoryLayout $LAYOUT() {
        return POLICYQUALINFO_st.$struct$LAYOUT;
    }
    static final VarHandle pqualid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("pqualid"));
    public static VarHandle pqualid$VH() {
        return POLICYQUALINFO_st.pqualid$VH;
    }
    public static MemoryAddress pqualid$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)POLICYQUALINFO_st.pqualid$VH.get(seg);
    }
    public static void pqualid$set( MemorySegment seg, MemoryAddress x) {
        POLICYQUALINFO_st.pqualid$VH.set(seg, x);
    }
    public static MemoryAddress pqualid$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)POLICYQUALINFO_st.pqualid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void pqualid$set(MemorySegment seg, long index, MemoryAddress x) {
        POLICYQUALINFO_st.pqualid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static class d {

        static final MemoryLayout d$union$LAYOUT = MemoryLayout.unionLayout(
            ADDRESS.withName("cpsuri"),
            ADDRESS.withName("usernotice"),
            ADDRESS.withName("other")
        );
        public static MemoryLayout $LAYOUT() {
            return d.d$union$LAYOUT;
        }
        static final VarHandle cpsuri$VH = d$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("cpsuri"));
        public static VarHandle cpsuri$VH() {
            return d.cpsuri$VH;
        }
        public static MemoryAddress cpsuri$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)d.cpsuri$VH.get(seg);
        }
        public static void cpsuri$set( MemorySegment seg, MemoryAddress x) {
            d.cpsuri$VH.set(seg, x);
        }
        public static MemoryAddress cpsuri$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)d.cpsuri$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void cpsuri$set(MemorySegment seg, long index, MemoryAddress x) {
            d.cpsuri$VH.set(seg.asSlice(index*sizeof()), x);
        }
        static final VarHandle usernotice$VH = d$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("usernotice"));
        public static VarHandle usernotice$VH() {
            return d.usernotice$VH;
        }
        public static MemoryAddress usernotice$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)d.usernotice$VH.get(seg);
        }
        public static void usernotice$set( MemorySegment seg, MemoryAddress x) {
            d.usernotice$VH.set(seg, x);
        }
        public static MemoryAddress usernotice$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)d.usernotice$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void usernotice$set(MemorySegment seg, long index, MemoryAddress x) {
            d.usernotice$VH.set(seg.asSlice(index*sizeof()), x);
        }
        static final VarHandle other$VH = d$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("other"));
        public static VarHandle other$VH() {
            return d.other$VH;
        }
        public static MemoryAddress other$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)d.other$VH.get(seg);
        }
        public static void other$set( MemorySegment seg, MemoryAddress x) {
            d.other$VH.set(seg, x);
        }
        public static MemoryAddress other$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)d.other$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void other$set(MemorySegment seg, long index, MemoryAddress x) {
            d.other$VH.set(seg.asSlice(index*sizeof()), x);
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

    public static MemorySegment d$slice(MemorySegment seg) {
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


