// Generated by jextract

package org.apache.tomcat.util.openssl;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import jdk.incubator.foreign.*;
import static jdk.incubator.foreign.ValueLayout.*;
public class v3_ext_ctx {

    static final MemoryLayout $struct$LAYOUT = MemoryLayout.structLayout(
        JAVA_INT.withName("flags"),
        MemoryLayout.paddingLayout(32),
        ADDRESS.withName("issuer_cert"),
        ADDRESS.withName("subject_cert"),
        ADDRESS.withName("subject_req"),
        ADDRESS.withName("crl"),
        ADDRESS.withName("db_meth"),
        ADDRESS.withName("db")
    ).withName("v3_ext_ctx");
    public static MemoryLayout $LAYOUT() {
        return v3_ext_ctx.$struct$LAYOUT;
    }
    static final VarHandle flags$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("flags"));
    public static VarHandle flags$VH() {
        return v3_ext_ctx.flags$VH;
    }
    public static int flags$get(MemorySegment seg) {
        return (int)v3_ext_ctx.flags$VH.get(seg);
    }
    public static void flags$set( MemorySegment seg, int x) {
        v3_ext_ctx.flags$VH.set(seg, x);
    }
    public static int flags$get(MemorySegment seg, long index) {
        return (int)v3_ext_ctx.flags$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void flags$set(MemorySegment seg, long index, int x) {
        v3_ext_ctx.flags$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle issuer_cert$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("issuer_cert"));
    public static VarHandle issuer_cert$VH() {
        return v3_ext_ctx.issuer_cert$VH;
    }
    public static MemoryAddress issuer_cert$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.issuer_cert$VH.get(seg);
    }
    public static void issuer_cert$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_ctx.issuer_cert$VH.set(seg, x);
    }
    public static MemoryAddress issuer_cert$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.issuer_cert$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void issuer_cert$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_ctx.issuer_cert$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle subject_cert$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("subject_cert"));
    public static VarHandle subject_cert$VH() {
        return v3_ext_ctx.subject_cert$VH;
    }
    public static MemoryAddress subject_cert$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.subject_cert$VH.get(seg);
    }
    public static void subject_cert$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_ctx.subject_cert$VH.set(seg, x);
    }
    public static MemoryAddress subject_cert$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.subject_cert$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void subject_cert$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_ctx.subject_cert$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle subject_req$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("subject_req"));
    public static VarHandle subject_req$VH() {
        return v3_ext_ctx.subject_req$VH;
    }
    public static MemoryAddress subject_req$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.subject_req$VH.get(seg);
    }
    public static void subject_req$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_ctx.subject_req$VH.set(seg, x);
    }
    public static MemoryAddress subject_req$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.subject_req$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void subject_req$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_ctx.subject_req$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle crl$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("crl"));
    public static VarHandle crl$VH() {
        return v3_ext_ctx.crl$VH;
    }
    public static MemoryAddress crl$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.crl$VH.get(seg);
    }
    public static void crl$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_ctx.crl$VH.set(seg, x);
    }
    public static MemoryAddress crl$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.crl$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void crl$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_ctx.crl$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle db_meth$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("db_meth"));
    public static VarHandle db_meth$VH() {
        return v3_ext_ctx.db_meth$VH;
    }
    public static MemoryAddress db_meth$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.db_meth$VH.get(seg);
    }
    public static void db_meth$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_ctx.db_meth$VH.set(seg, x);
    }
    public static MemoryAddress db_meth$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.db_meth$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void db_meth$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_ctx.db_meth$VH.set(seg.asSlice(index*sizeof()), x);
    }
    static final VarHandle db$VH = $struct$LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("db"));
    public static VarHandle db$VH() {
        return v3_ext_ctx.db$VH;
    }
    public static MemoryAddress db$get(MemorySegment seg) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.db$VH.get(seg);
    }
    public static void db$set( MemorySegment seg, MemoryAddress x) {
        v3_ext_ctx.db$VH.set(seg, x);
    }
    public static MemoryAddress db$get(MemorySegment seg, long index) {
        return (jdk.incubator.foreign.MemoryAddress)v3_ext_ctx.db$VH.get(seg.asSlice(index*sizeof()));
    }
    public static void db$set(MemorySegment seg, long index, MemoryAddress x) {
        v3_ext_ctx.db$VH.set(seg.asSlice(index*sizeof()), x);
    }
    public static long sizeof() { return $LAYOUT().byteSize(); }
    public static MemorySegment allocate(SegmentAllocator allocator) { return allocator.allocate($LAYOUT()); }
    public static MemorySegment allocateArray(int len, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(len, $LAYOUT()));
    }
    public static MemorySegment ofAddress(MemoryAddress addr, ResourceScope scope) { return RuntimeHelper.asArray(addr, $LAYOUT(), 1, scope); }
}


