/*
 * @(#) $Id: JSTKBuffer.java,v 1.1.1.1 2003/10/05 18:39:22 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.ssl;

import java.nio.ByteBuffer;

import org.jstk.JSTKArgs;
import org.jstk.JSTKOptions;


public abstract class JSTKBuffer {

    public static class NIOByteBuffer extends JSTKBuffer {

        private final ByteBuffer bb;

        protected NIOByteBuffer(int bufsize) {
            bb = ByteBuffer.allocateDirect(bufsize);
        }

        @Override
        public int length() {
            return bb.capacity();
        }

        @Override
        public int getNBytes() {
            return bb.position();
        }

        @Override
        public void setNBytes(int n) {
        }

        @Override
        public byte[] getBytes() {
            bb.flip();
            byte[] buf = new byte[bb.limit()];
            bb.get(buf);
            bb.clear();
            return buf;
        }

        @Override
        public void putBytes(byte[] buf) {
            bb.put(buf);
        }

        @Override
        public void putBytes(byte[] buf, int off, int len) {
            bb.put(buf, off, len);
        }

        @Override
        public ByteBuffer getByteBuffer() {
            return bb;
        }

        @Override
        public byte[] getByteArray() {
            return null;
        }

        @Override
        public void clear() {
            bb.clear();
        }
    }

    public static class OrdByteBuffer extends JSTKBuffer {

        final byte[] buf;

        int n;

        protected OrdByteBuffer(int bufsize) {
            buf = new byte[bufsize];
            n = 0;
        }

        @Override
        public int length() {
            return buf.length;
        }

        @Override
        public int getNBytes() {
            return n;
        }

        @Override
        public void setNBytes(int n) {
            this.n = n;
        }

        @Override
        public byte[] getBytes() {
            byte[] tbuf = new byte[n];
            System.arraycopy(buf, 0, tbuf, 0, n);
            n = 0;
            return tbuf;
        }

        @Override
        public void putBytes(byte[] tbuf) {
            System.arraycopy(tbuf, 0, buf, n, tbuf.length);
            n += tbuf.length;
        }

        @Override
        public void putBytes(byte[] tbuf, int off, int len) {
            System.arraycopy(tbuf, off, buf, n, len);
            n += len;
        }

        @Override
        public ByteBuffer getByteBuffer() {
            return null;
        }

        @Override
        public byte[] getByteArray() {
            return buf;
        }

        @Override
        public void clear() {
        }
    }

    public static JSTKBuffer getInstance(int bufsize, JSTKArgs args) {
        boolean nio = Boolean.parseBoolean(args.get("nio"));
        if (nio)
            return new NIOByteBuffer(bufsize);
        else
            return new OrdByteBuffer(bufsize);
    }

    public static JSTKBuffer getInstance(int bufsize) {
        return new NIOByteBuffer(bufsize);
    }

    public abstract int length();

    public abstract int getNBytes();

    public abstract void setNBytes(int n);

    public abstract byte[] getBytes();

    public abstract void putBytes(byte[] buf);

    public abstract void putBytes(byte[] buf, int off, int len);

    public abstract ByteBuffer getByteBuffer();

    public abstract byte[] getByteArray();

    public abstract void clear();

    public static void main(String[] args) {
        JSTKOptions opts = new JSTKOptions();
        opts.parse(args, 0);
        byte[] buf;
        String data = "test data";
        JSTKBuffer jb = JSTKBuffer.getInstance(1024, opts);

        System.out.println("First Round::");
        System.out.println("jb.length() = " + jb.length() + ", jb.bytes() = " + jb.getNBytes());
        jb.putBytes(data.getBytes());
        System.out.println("jb.length() = " + jb.length() + ", jb.bytes() = " + jb.getNBytes());
        buf = jb.getBytes();
        System.out.println("buf = " + new String(buf));

        System.out.println("Second Round::");
        System.out.println("jb.length() = " + jb.length() + ", jb.bytes() = " + jb.getNBytes());
        jb.putBytes(data.getBytes());
        System.out.println("jb.length() = " + jb.length() + ", jb.bytes() = " + jb.getNBytes());
        buf = jb.getBytes();
        System.out.println("buf = " + new String(buf));
    }
}
