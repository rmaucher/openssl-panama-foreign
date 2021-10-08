// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class v3_ext_method {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_INT.withName("ext_nid"),
        JAVA_INT.withName("ext_flags"),
        ADDRESS.withName("it"),
        ADDRESS.withName("ext_new"),
        ADDRESS.withName("ext_free"),
        ADDRESS.withName("d2i"),
        ADDRESS.withName("i2d"),
        ADDRESS.withName("i2s"),
        ADDRESS.withName("s2i"),
        ADDRESS.withName("i2v"),
        ADDRESS.withName("v2i"),
        ADDRESS.withName("i2r"),
        ADDRESS.withName("r2i"),
        ADDRESS.withName("usr_data")
    ).withName("v3_ext_method");
    public static MemoryLayout $LAYOUT() {
        return v3_ext_method.$struct$LAYOUT;
    }
    static final VarHandle ext_nid$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("ext_nid"));
    public static VarHandle ext_nid$VH() {
        return v3_ext_method.ext_nid$VH;
    }
    public static int ext_nid$get(MemorySegment seg) {
        return (int)v3_ext_method.ext_nid$VH.get(seg);
    }
    public static void ext_nid$set( MemorySegment seg, int x) {
        v3_ext_method.ext_nid$VH.set(seg, x);
    }
    public static int ext_nid$get(MemorySegment seg, long index) {
        return (int)v3_ext_method.ext_nid$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void ext_nid$set(MemorySegment seg, long index, int x) {
        v3_ext_method.ext_nid$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle ext_flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("ext_flags"));
    public static VarHandle ext_flags$VH() {
        return v3_ext_method.ext_flags$VH;
    }
    public static int ext_flags$get(MemorySegment seg) {
        return (int)v3_ext_method.ext_flags$VH.get(seg);
    }
    public static void ext_flags$set( MemorySegment seg, int x) {
        v3_ext_method.ext_flags$VH.set(seg, x);
    }
    public static int ext_flags$get(MemorySegment seg, long index) {
        return (int)v3_ext_method.ext_flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void ext_flags$set(MemorySegment seg, long index, int x) {
        v3_ext_method.ext_flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle it$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("it"));
    public static VarHandle it$VH() {
        return v3_ext_method.it$VH;
    }
    public static MemoryAddress it$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.it$VH.get(seg);
    }
    public static void it$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.it$VH.set(seg, x);
    }
    public static MemoryAddress it$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.it$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void it$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.it$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle ext_new$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("ext_new"));
    public static VarHandle ext_new$VH() {
        return v3_ext_method.ext_new$VH;
    }
    public static MemoryAddress ext_new$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.ext_new$VH.get(seg);
    }
    public static void ext_new$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.ext_new$VH.set(seg, x);
    }
    public static MemoryAddress ext_new$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.ext_new$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void ext_new$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.ext_new$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_NEW ext_new (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_NEW.ofAddress(ext_new$get(segment), scope);
    }
    static final VarHandle ext_free$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("ext_free"));
    public static VarHandle ext_free$VH() {
        return v3_ext_method.ext_free$VH;
    }
    public static MemoryAddress ext_free$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.ext_free$VH.get(seg);
    }
    public static void ext_free$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.ext_free$VH.set(seg, x);
    }
    public static MemoryAddress ext_free$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.ext_free$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void ext_free$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.ext_free$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_FREE ext_free (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_FREE.ofAddress(ext_free$get(segment), scope);
    }
    static final VarHandle d2i$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("d2i"));
    public static VarHandle d2i$VH() {
        return v3_ext_method.d2i$VH;
    }
    public static MemoryAddress d2i$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.d2i$VH.get(seg);
    }
    public static void d2i$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.d2i$VH.set(seg, x);
    }
    public static MemoryAddress d2i$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.d2i$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void d2i$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.d2i$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_D2I d2i (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_D2I.ofAddress(d2i$get(segment), scope);
    }
    static final VarHandle i2d$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("i2d"));
    public static VarHandle i2d$VH() {
        return v3_ext_method.i2d$VH;
    }
    public static MemoryAddress i2d$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2d$VH.get(seg);
    }
    public static void i2d$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.i2d$VH.set(seg, x);
    }
    public static MemoryAddress i2d$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2d$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void i2d$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.i2d$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_I2D i2d (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_I2D.ofAddress(i2d$get(segment), scope);
    }
    static final VarHandle i2s$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("i2s"));
    public static VarHandle i2s$VH() {
        return v3_ext_method.i2s$VH;
    }
    public static MemoryAddress i2s$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2s$VH.get(seg);
    }
    public static void i2s$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.i2s$VH.set(seg, x);
    }
    public static MemoryAddress i2s$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2s$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void i2s$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.i2s$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_I2S i2s (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_I2S.ofAddress(i2s$get(segment), scope);
    }
    static final VarHandle s2i$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("s2i"));
    public static VarHandle s2i$VH() {
        return v3_ext_method.s2i$VH;
    }
    public static MemoryAddress s2i$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.s2i$VH.get(seg);
    }
    public static void s2i$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.s2i$VH.set(seg, x);
    }
    public static MemoryAddress s2i$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.s2i$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void s2i$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.s2i$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_S2I s2i (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_S2I.ofAddress(s2i$get(segment), scope);
    }
    static final VarHandle i2v$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("i2v"));
    public static VarHandle i2v$VH() {
        return v3_ext_method.i2v$VH;
    }
    public static MemoryAddress i2v$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2v$VH.get(seg);
    }
    public static void i2v$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.i2v$VH.set(seg, x);
    }
    public static MemoryAddress i2v$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2v$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void i2v$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.i2v$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_I2V i2v (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_I2V.ofAddress(i2v$get(segment), scope);
    }
    static final VarHandle v2i$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("v2i"));
    public static VarHandle v2i$VH() {
        return v3_ext_method.v2i$VH;
    }
    public static MemoryAddress v2i$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.v2i$VH.get(seg);
    }
    public static void v2i$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.v2i$VH.set(seg, x);
    }
    public static MemoryAddress v2i$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.v2i$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void v2i$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.v2i$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_V2I v2i (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_V2I.ofAddress(v2i$get(segment), scope);
    }
    static final VarHandle i2r$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("i2r"));
    public static VarHandle i2r$VH() {
        return v3_ext_method.i2r$VH;
    }
    public static MemoryAddress i2r$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2r$VH.get(seg);
    }
    public static void i2r$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.i2r$VH.set(seg, x);
    }
    public static MemoryAddress i2r$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.i2r$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void i2r$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.i2r$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_I2R i2r (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_I2R.ofAddress(i2r$get(segment), scope);
    }
    static final VarHandle r2i$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("r2i"));
    public static VarHandle r2i$VH() {
        return v3_ext_method.r2i$VH;
    }
    public static MemoryAddress r2i$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.r2i$VH.get(seg);
    }
    public static void r2i$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.r2i$VH.set(seg, x);
    }
    public static MemoryAddress r2i$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.r2i$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void r2i$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.r2i$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static X509V3_EXT_R2I r2i (MemorySegment segment, ResourceScope scope) {
        return X509V3_EXT_R2I.ofAddress(r2i$get(segment), scope);
    }
    static final VarHandle usr_data$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("usr_data"));
    public static VarHandle usr_data$VH() {
        return v3_ext_method.usr_data$VH;
    }
    public static MemoryAddress usr_data$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.usr_data$VH.get(seg);
    }
    public static void usr_data$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_method.usr_data$VH.set(seg, x);
    }
    public static MemoryAddress usr_data$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_method.usr_data$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void usr_data$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_method.usr_data$VH.set(seg.asSlice(index*sizeof()), x);
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


