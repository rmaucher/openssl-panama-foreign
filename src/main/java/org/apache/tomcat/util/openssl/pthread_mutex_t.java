// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class pthread_mutex_t {

    static final MemoryLayout $union$LAYOUT = MemoryLayout.unionLayout(
        MemoryLayout.structLayout(
            JAVA_INT.withName("__lock"),
            JAVA_INT.withName("__count"),
            JAVA_INT.withName("__owner"),
            JAVA_INT.withName("__nusers"),
            JAVA_INT.withName("__kind"),
            JAVA_SHORT.withName("__spins"),
            JAVA_SHORT.withName("__elision"),
            MemoryLayout.structLayout(
                ADDRESS.withName("__prev"),
                ADDRESS.withName("__next")
            ).withName("__list")
        ).withName("__data"),
        MemoryLayout.sequenceLayout(40, JAVA_BYTE).withName("__size"),
        JAVA_LONG.withName("__align")
    );
    public static MemoryLayout $LAYOUT() {
        return pthread_mutex_t.$union$LAYOUT;
    }
    public static MemorySegment __data$slice(MemorySegment seg) {
        return seg.asSlice(0, 40);
    }
    public static MemorySegment __size$slice(MemorySegment seg) {
        return seg.asSlice(0, 40);
    }
    static final VarHandle __align$VH = $union$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("__align"));
    public static VarHandle __align$VH() {
        return pthread_mutex_t.__align$VH;
    }
    public static long __align$get(MemorySegment seg) {
        return (long)pthread_mutex_t.__align$VH.get(seg);
    }
    public static void __align$set( MemorySegment seg, long x) {
        pthread_mutex_t.__align$VH.set(seg, x);
    }
    public static long __align$get(MemorySegment seg, long index) {
        return (long)pthread_mutex_t.__align$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void __align$set(MemorySegment seg, long index, long x) {
        pthread_mutex_t.__align$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


