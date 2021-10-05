// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class IPAddressChoice_st {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_INT.withName("type"),
        MemoryLayout.paddingLayout(32),
        MemoryLayout.unionLayout(
            ADDRESS.withName("inherit"),
            ADDRESS.withName("addressesOrRanges")
        ).withName("u")
    ).withName("IPAddressChoice_st");
    public static MemoryLayout $LAYOUT() {
        return IPAddressChoice_st.$struct$LAYOUT;
    }
    static final VarHandle type$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("type"));
    public static VarHandle type$VH() {
        return IPAddressChoice_st.type$VH;
    }
    public static int type$get(MemorySegment seg) {
        return (int)IPAddressChoice_st.type$VH.get(seg);
    }
    public static void type$set( MemorySegment seg, int x) {
        IPAddressChoice_st.type$VH.set(seg, x);
    }
    public static int type$get(MemorySegment seg, long index) {
        return (int)IPAddressChoice_st.type$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void type$set(MemorySegment seg, long index, int x) {
        IPAddressChoice_st.type$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static class u {

        static final MemoryLayout u$union$LAYOUT = MemoryLayout.unionLayout(
            ADDRESS.withName("inherit"),
            ADDRESS.withName("addressesOrRanges")
        );
        public static MemoryLayout $LAYOUT() {
            return u.u$union$LAYOUT;
        }
        static final VarHandle inherit$VH = u$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("inherit"));
        public static VarHandle inherit$VH() {
            return u.inherit$VH;
        }
        public static MemoryAddress inherit$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)u.inherit$VH.get(seg);
        }
        public static void inherit$set( MemorySegment seg, MemoryAddress x) {
            u.inherit$VH.set(seg, x);
        }
        public static MemoryAddress inherit$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)u.inherit$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void inherit$set(MemorySegment seg, long index, MemoryAddress x) {
            u.inherit$VH.set(seg.asSlice(index*sizeof()), x);
        }
        static final VarHandle addressesOrRanges$VH = u$union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("addressesOrRanges"));
        public static VarHandle addressesOrRanges$VH() {
            return u.addressesOrRanges$VH;
        }
        public static MemoryAddress addressesOrRanges$get(MemorySegment seg) {
            return (jdk.incubator.foreign.MemoryAddress)u.addressesOrRanges$VH.get(seg);
        }
        public static void addressesOrRanges$set( MemorySegment seg, MemoryAddress x) {
            u.addressesOrRanges$VH.set(seg, x);
        }
        public static MemoryAddress addressesOrRanges$get(MemorySegment seg, long index) {
            return (jdk.incubator.foreign.MemoryAddress)u.addressesOrRanges$VH.get(seg.asSlice(index*sizeof()));
        }
        public static void addressesOrRanges$set(MemorySegment seg, long index, MemoryAddress x) {
            u.addressesOrRanges$VH.set(seg.asSlice(index*sizeof()), x);
        }
        public static long sizeof() { return $LAYOUT().byteSize(); }
        public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
        public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
            return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
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
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}

