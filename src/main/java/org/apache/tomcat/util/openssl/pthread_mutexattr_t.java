// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class pthread_mutexattr_t {

    static final MemoryLayout $union$LAYOUT = MemoryLayout.unionLayout(
        MemoryLayout.sequenceLayout(4, JAVA_BYTE).withName("__size"),
        JAVA_INT.withName("__align")
    );
    public static MemoryLayout $LAYOUT() {
        return pthread_mutexattr_t.$union$LAYOUT;
    }
    public static MemorySegment __size$slice(MemorySegment seg) {
        return seg.asSlice(0, 4);
    }
    static final VarHandle __align$VH = $union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("__align"));
    public static VarHandle __align$VH() {
        return pthread_mutexattr_t.__align$VH;
    }
    public static int __align$get(MemorySegment seg) {
        return (int)pthread_mutexattr_t.__align$VH.get(seg);
    }
    public static void __align$set( MemorySegment seg, int x) {
        pthread_mutexattr_t.__align$VH.set(seg, x);
    }
    public static int __align$get(MemorySegment seg, long index) {
        return (int)pthread_mutexattr_t.__align$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void __align$set(MemorySegment seg, long index, int x) {
        pthread_mutexattr_t.__align$VH.set(seg.asSlice(index*sizeof()), x);
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


