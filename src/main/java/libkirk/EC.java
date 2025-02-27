/*
 * Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
 * Licensed under the terms of the GNU GPL, version 2
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 * Modified for Kirk engine by setting single curve and internal function
 * to support Kirk elliptic curve options.- July 2011
 * Ported to Java by gid15
*/

package libkirk;

import java.util.Arrays;

import libkirk.KirkEngine.ECDSA_POINT;
import vavi.util.StringUtil;

import static java.lang.System.arraycopy;
import static libkirk.Utilities.log;
import static libkirk.Utilities.memcpy;
import static libkirk.Utilities.u8;


/**
 * Ported to Java from
 * @see "https://github.com/ProximaV/kirk-engine-full/blob/master/libkirk/ec.c"
 * @see "https://github.com/ProximaV/kirk-engine-full/blob/master/libkirk/ec.h"
 */
public class EC {

	public static final int ELT_SIZE = 20;
	public static final int BIGNUMBER_SIZE = 21;

	public static class ECPoint {
		public final byte[] x = new byte[ELT_SIZE];
		public final byte[] y = new byte[ELT_SIZE];

		public ECPoint() {
		}

		public ECPoint(ECPoint p) {
			arraycopy(p.x, 0, x, 0, ELT_SIZE);
			arraycopy(p.y, 0, y, 0, ELT_SIZE);
		}
	}

	static private final byte[] ec_p = new byte[ELT_SIZE];
	static private final byte[] ec_a = new byte[ELT_SIZE];
	static private final byte[] ec_b = new byte[ELT_SIZE];
	static private final byte[] ec_N = new byte[BIGNUMBER_SIZE];
	static private final ECPoint ec_G = new ECPoint(); // mon
	static private final ECPoint ec_Q = new ECPoint(); // mon
	static private final byte[] ec_k = new byte[BIGNUMBER_SIZE];

	public static void hex_dump(String str, byte[] buf, int size) {
		hex_dump(str, buf, 0, size);
	}

	public static void hex_dump(String str, byte[] buf, int offset, int size) {
		log.finer(String.format("%s: %s", str, StringUtil.getDump(buf, offset, size)));
	}

	public static void elt_copy(byte[] d, byte[] a) {
		elt_copy(d, 0, a, 0);
	}

	public static void elt_copy(byte[] d, int offsetDst, byte[] a, int offsetSrc) {
		arraycopy(a, offsetSrc, d, offsetDst, ELT_SIZE);
	}

	public static void elt_zero(byte[] d) {
		elt_zero(d, 0);
	}

	public static void elt_zero(byte[] d, int offsetDst) {
		Arrays.fill(d, offsetDst, offsetDst + ELT_SIZE, (byte) 0);
	}

	public static boolean elt_is_zero(byte[] d) {
		return elt_is_zero(d, 0);
	}

	public static boolean elt_is_zero(byte[] d, int offsetDst) {
		for (int i = 0; i < ELT_SIZE; i++) {
			if (d[offsetDst + i] != (byte) 0) {
				return false;
			}
		}

		return true;
	}

	public static void elt_add(byte[] d, byte[] a, byte[] b) {
		elt_add(d, 0, a, 0, b, 0);
	}

	public static void elt_add(byte[] d, int offsetDst, byte[] a, int offset1, byte[] b, int offset2) {
		BN.bn_add(d, offsetDst, a, offset1, b, offset2, ec_p, 0, ELT_SIZE);
	}

	public static void elt_sub(byte[] d, byte[] a, byte[] b) {
		elt_sub(d, 0, a, 0, b, 0);
	}

	public static void elt_sub(byte[] d, int offsetDst, byte[] a, int offset1, byte[] b, int offset2) {
		BN.bn_sub(d, offsetDst, a, offset1, b, offset2, ec_p, 0, ELT_SIZE);
	}

	public static void elt_mul(byte[] d, byte[] a, byte[] b) {
		elt_mul(d, 0, a, 0, b, 0);
	}

	public static void elt_mul(byte[] d, int offsetDst, byte[] a, int offset1, byte[] b, int offset2) {
		BN.bn_mon_mul(d, offsetDst, a, offset1, b, offset2, ec_p, 0, ELT_SIZE);
	}

	public static void elt_square(byte[] d, byte[] a) {
		elt_square(d, 0, a, 0);
	}

	public static void elt_square(byte[] d, int offsetDst, byte[] a, int offset1) {
		elt_mul(d, offsetDst, a, offset1, a, offset1);
	}

	public static void elt_inv(byte[] d, byte[] a) {
		elt_inv(d, 0, a, 0);
	}

	public static void elt_inv(byte[] d, int offsetDst, byte[] a, int offset1) {
		byte[] s = new byte[ELT_SIZE];
		elt_copy(s, 0, a, offset1);
		BN.bn_mon_inv(d, offsetDst, s, 0, ec_p, 0, ELT_SIZE);
	}

	public static void point_to_mon(ECPoint p) {
		BN.bn_to_mon(p.x, 0, ec_p, 0, ELT_SIZE);
		BN.bn_to_mon(p.y, 0, ec_p, 0, ELT_SIZE);
	}

	public static void point_from_mon(ECPoint p) {
		BN.bn_from_mon(p.x, 0, ec_p, 0, ELT_SIZE);
		BN.bn_from_mon(p.y, 0, ec_p, 0, ELT_SIZE);
	}

	public static void point_zero(ECPoint p) {
		elt_zero(p.x, 0);
		elt_zero(p.y, 0);
	}

	public static boolean point_is_zero(ECPoint p) {
		return elt_is_zero(p.x, 0) && elt_is_zero(p.y, 0);
	}

	public static void point_double(ECPoint r, ECPoint p) {
		byte[] s = new byte[ELT_SIZE];
		byte[] t = new byte[ELT_SIZE];
		ECPoint pp = new ECPoint(p);
		byte[] px = pp.x;
		byte[] py = pp.y;
		byte[] rx = r.x;
		byte[] ry = r.y;

		if (elt_is_zero(py)) {
			point_zero(r);
			return;
		}

		elt_square(t, px);  // t = px*px
		elt_add(s, t, t); // s = 2*px*px
		elt_add(s, s, t); // s = 3*px*px
		elt_add(s, s, ec_a);  // s = 3*px*px + a
		elt_add(t, py, py); // t = 2*py
		elt_inv(t, t);    // t = 1/(2*py)
		elt_mul(s, s, t); // s = (3*px*px+a)/(2*py)

		elt_square(rx, s);  // rx = s*s
		elt_add(t, px, px); // t = 2*px
		elt_sub(rx, rx, t); // rx = s*s - 2*px

		elt_sub(t, px, rx); // t = -(rx-px)
		elt_mul(ry, s, t);  // ry = -s*(rx-px)
		elt_sub(ry, ry, py);  // ry = -s*(rx-px) - py
	}

	public static void point_add(ECPoint r, ECPoint p, ECPoint q) {
		byte[] s = new byte[ELT_SIZE];
		byte[] t = new byte[ELT_SIZE];
		byte[] u = new byte[ELT_SIZE];
		ECPoint pp = new ECPoint(p);
		ECPoint qq = new ECPoint(q);
		byte[] px = pp.x;
		byte[] py = pp.y;
		byte[] qx = qq.x;
		byte[] qy = qq.y;
		byte[] rx = r.x;
		byte[] ry = r.y;

		if (point_is_zero(pp)) {
			elt_copy(rx, qx);
			elt_copy(ry, qy);
			return;
		}

		if (point_is_zero(qq)) {
			elt_copy(rx, px);
			elt_copy(ry, py);
			return;
		}

		elt_sub(u, qx, px);

		if (elt_is_zero(u)) {
			elt_sub(u, qy, py);
			if (elt_is_zero(u)) {
				point_double(r, pp);
			} else {
				point_zero(r);
			}
			return;
		}

		elt_inv(t, u);    // t = 1/(qx-px)
		elt_sub(u, qy, py); // u = qy-py
		elt_mul(s, t, u); // s = (qy-py)/(qx-px)

		elt_square(rx, s);  // rx = s*s
		elt_add(t, px, qx); // t = px+qx
		elt_sub(rx, rx, t); // rx = s*s - (px+qx)

		elt_sub(t, px, rx); // t = -(rx-px)
		elt_mul(ry, s, t);  // ry = -s*(rx-px)
		elt_sub(ry, ry, py);  // ry = -s*(rx-px) - py
	}

	public static void point_mul(ECPoint d, byte[] a, ECPoint b) { // a is bignum
		point_mul(d, a, 0, b);
	}

	public static void point_mul(ECPoint d, byte[] a, int offset, ECPoint b) { // a is bignum
		point_zero(d);

		for (int i = 0; i < BIGNUMBER_SIZE; i++) {
			for (int mask = 0x80; mask != 0; mask >>= 1) {
				point_double(d, d);
				if ((u8(a, offset + i) & mask) != 0) {
					point_add(d, d, b);
				}
			}
		}
	}

	public static void generate_ecdsa(byte[] outR, byte[] outS, byte[] k, byte[] hash) {
		generate_ecdsa(outR, 0, outS, 0, k, 0, hash, 0);
	}

	public static void generate_ecdsa(byte[] outR, int outRoffset, byte[] outS, int outSoffset, byte[] k, int koffset, byte[] hash, int hashoffset) {
		byte[] e = new byte[BIGNUMBER_SIZE];
		byte[] kk = new byte[BIGNUMBER_SIZE];
		byte[] m = new byte[BIGNUMBER_SIZE];
		byte[] R = new byte[BIGNUMBER_SIZE];
		byte[] S = new byte[BIGNUMBER_SIZE];
		byte[] minv = new byte[BIGNUMBER_SIZE];
		ECPoint mG = new ECPoint();

		//e[0] = 0;R[0] = 0;S[0] = 0;
		arraycopy(hash, hashoffset, e, 1, ELT_SIZE);
		BN.bn_reduce(e, ec_N, BIGNUMBER_SIZE);

		KirkEngine.kirk_CMD14(m, 1, ELT_SIZE);
		//m[0] = 0;

		point_mul(mG, m, ec_G);
		point_from_mon(mG);
		//R[0] = 0;
		elt_copy(R, 1, mG.x, 0);

		//  S = m**-1*(e + Rk) (mod N)
		BN.bn_copy(kk, k, BIGNUMBER_SIZE);
		BN.bn_reduce(kk, ec_N, BIGNUMBER_SIZE);
		BN.bn_to_mon(m, ec_N, BIGNUMBER_SIZE);
		BN.bn_to_mon(e, ec_N, BIGNUMBER_SIZE);
		BN.bn_to_mon(R, ec_N, BIGNUMBER_SIZE);
		BN.bn_to_mon(kk, ec_N, BIGNUMBER_SIZE);

		BN.bn_mon_mul(S, R, kk, ec_N, BIGNUMBER_SIZE);
		BN.bn_add(kk, S, e, ec_N, BIGNUMBER_SIZE);
		BN.bn_mon_inv(minv, m, ec_N, BIGNUMBER_SIZE);
		BN.bn_mon_mul(S, minv, kk, ec_N, BIGNUMBER_SIZE);

		BN.bn_from_mon(R, ec_N, BIGNUMBER_SIZE);
		BN.bn_from_mon(S, ec_N, BIGNUMBER_SIZE);
		arraycopy(R, 1, outR, outRoffset, BIGNUMBER_SIZE - 1);
		arraycopy(S, 1, outS, outSoffset, BIGNUMBER_SIZE - 1);
	}

	public static boolean check_ecdsa(ECPoint Q, byte[] inR, byte[] inS, byte[] hash) {
		return check_ecdsa(Q, inR, 0, inS, 0, hash, 0);
	}

	public static boolean check_ecdsa(ECPoint Q, byte[] inR, int inRoffset, byte[] inS, int inSoffset, byte[] hash, int hashoffset) {
		byte[] Sinv = new byte[BIGNUMBER_SIZE];
		byte[] e = new byte[BIGNUMBER_SIZE];
		byte[] R = new byte[BIGNUMBER_SIZE];
		byte[] S = new byte[BIGNUMBER_SIZE];
		byte[] w1 = new byte[BIGNUMBER_SIZE];
		byte[] w2 = new byte[BIGNUMBER_SIZE];
		byte[] rr = new byte[BIGNUMBER_SIZE];
		ECPoint r1 = new ECPoint();
		ECPoint r2 = new ECPoint();

		//e[0] = 0;
		arraycopy(hash, hashoffset, e, 1, ELT_SIZE);
		BN.bn_reduce(e, ec_N, BIGNUMBER_SIZE);
		//R[0] = 0;
		arraycopy(inR, inRoffset, R, 1, ELT_SIZE);
		BN.bn_reduce(R, ec_N, BIGNUMBER_SIZE);
		//S[0] = 0;
		arraycopy(inS, inSoffset, S, 1, ELT_SIZE);
		BN.bn_reduce(S, ec_N, BIGNUMBER_SIZE);

		BN.bn_to_mon(R, ec_N, BIGNUMBER_SIZE);
		BN.bn_to_mon(S, ec_N, BIGNUMBER_SIZE);
		BN.bn_to_mon(e, ec_N, BIGNUMBER_SIZE);
		// make Sinv = 1/S
		BN.bn_mon_inv(Sinv, S, ec_N, BIGNUMBER_SIZE);
		// w1 = m * Sinv
		BN.bn_mon_mul(w1, e, Sinv, ec_N, BIGNUMBER_SIZE);
		// w2 = r * Sinv
		BN.bn_mon_mul(w2, R, Sinv, ec_N, BIGNUMBER_SIZE);

		// mod N both
		BN.bn_from_mon(w1, ec_N, BIGNUMBER_SIZE);
		BN.bn_from_mon(w2, ec_N, BIGNUMBER_SIZE);

		// r1 = m/s * G
		point_mul(r1, w1, ec_G);
		// r2 = r/s * P
		point_mul(r2, w2, Q);

		//r1 = r1 + r2
		point_add(r1, r1, r2);

		point_from_mon(r1);

		//rr[0] = 0;
		arraycopy(r1.x, 0, rr, 1, ELT_SIZE);
		BN.bn_reduce(rr, ec_N, BIGNUMBER_SIZE);

		BN.bn_from_mon(R, ec_N, BIGNUMBER_SIZE);
		BN.bn_from_mon(S, ec_N, BIGNUMBER_SIZE);

		return BN.bn_compare(rr, R, BIGNUMBER_SIZE) == 0;
	}

	public static void ec_priv_to_pub(byte[] k, ECDSA_POINT Q) {
		ec_priv_to_pub(k, 0, Q);
	}

	public static void ec_priv_to_pub(byte[] k, int koffset, ECDSA_POINT Q) {
		ECPoint ec_temp = new ECPoint();
		BN.bn_to_mon(k, koffset, ec_N, 0, BIGNUMBER_SIZE);
		point_mul(ec_temp, k, koffset, ec_G);
		point_from_mon(ec_temp);
		//bn_from_mon(k, ec_N, 21);
		memcpy(Q.x, ec_temp.x, ELT_SIZE);
		memcpy(Q.y, ec_temp.y, ELT_SIZE);
	}

	public static void ec_pub_mult(byte[] k, byte[] Q) {
		ec_pub_mult(k, 0, Q, 0);
	}

	public static void ec_pub_mult(byte[] k, byte[] Q, int Qoffset) {
		ec_pub_mult(k, 0, Q, Qoffset);
	}

	public static void ec_pub_mult(byte[] k, int koffset, byte[] Q, int Qoffset) {
		ECPoint ec_temp = new ECPoint();
		//bn_to_mon(k, ec_N, 21);
		point_mul(ec_temp, k, koffset, ec_Q);
		point_from_mon(ec_temp);
		//bn_from_mon(k, ec_N, 21);
		arraycopy(ec_temp.x, 0, Q, Qoffset +  0, ELT_SIZE);
		arraycopy(ec_temp.y, 0, Q, Qoffset + 20, ELT_SIZE);
	}

	public static int ecdsa_set_curve(byte[] p, byte[] a, byte[] b, byte[] N, byte[] Gx, byte[] Gy) {
		return ecdsa_set_curve(p, 0, a, 0, b, 0, N, 0, Gx, 0, Gy, 0);
	}

	public static int ecdsa_set_curve(byte[] p, int poffset, byte[] a, int offset1, byte[] b, int offset2, byte[] N, int Noffset, byte[] Gx, int Gxoffset, byte[] Gy, int Gyoffset) {
		arraycopy(p, poffset, ec_p, 0, ELT_SIZE);
		arraycopy(a, offset1, ec_a, 0, ELT_SIZE);
		arraycopy(b, offset2, ec_b, 0, ELT_SIZE);
		arraycopy(N, Noffset, ec_N, 0, BIGNUMBER_SIZE);

		BN.bn_to_mon(ec_a, ec_p, ELT_SIZE);
		BN.bn_to_mon(ec_b, ec_p, ELT_SIZE);

		arraycopy(Gx, Gxoffset, ec_G.x, 0, ELT_SIZE);
		arraycopy(Gy, Gyoffset, ec_G.y, 0, ELT_SIZE);
		point_to_mon(ec_G);

		return 0;
	}

	public static void ecdsa_set_pub(ECDSA_POINT Q) {
		arraycopy(Q.x, 0, ec_Q.x, 0, ELT_SIZE);
		arraycopy(Q.y, 0, ec_Q.y, 0, ELT_SIZE);
		point_to_mon(ec_Q);
	}

	public static void ecdsa_set_pub(byte[] Q) {
		ecdsa_set_pub(Q, 0);
	}

	public static void ecdsa_set_pub(byte[] Q, int Qoffset) {
		arraycopy(Q, Qoffset, ec_Q.x, 0, ELT_SIZE);
		arraycopy(Q, Qoffset + ELT_SIZE, ec_Q.y, 0, ELT_SIZE);
		point_to_mon(ec_Q);
	}

	public static void ecdsa_set_priv(byte[] ink) {
		ecdsa_set_priv(ink, 0);
	}

	public static void ecdsa_set_priv(byte[] ink, int inkoffset) {
		byte[] k = new byte[BIGNUMBER_SIZE];
		//k[0]=0;
		arraycopy(ink, inkoffset, k, 1, ELT_SIZE);
		BN.bn_reduce(k, ec_N, BIGNUMBER_SIZE);

		arraycopy(k, 0, ec_k, 0, BIGNUMBER_SIZE);
	}

	public static boolean ecdsa_verify(byte[] hash, byte[] R, byte[] S) {
		return ecdsa_verify(hash, 0, R, 0, S, 0);
	}

	public static boolean ecdsa_verify(byte[] hash, int hashoffset, byte[] R, int Roffset, byte[] S, int Soffset) {
		return check_ecdsa(ec_Q, R, Roffset, S, Soffset, hash, hashoffset);
	}

	public static void ecdsa_sign(byte[] hash, byte[] R, byte[] S) {
		ecdsa_sign(hash, 0, R, 0, S, 0);
	}

	public static void ecdsa_sign(byte[] hash, int hashoffset, byte[] R, int Roffset, byte[] S, int Soffset) {
		generate_ecdsa(R, Roffset, S, Soffset, ec_k, 0, hash, hashoffset);
	}

	public static boolean point_is_on_curve(byte[] p, int offset) {
		byte[] s = new byte[ELT_SIZE];
		byte[] t = new byte[ELT_SIZE];

		byte[] x = new byte[ELT_SIZE];
		byte[] y = new byte[ELT_SIZE];
		arraycopy(p, offset, x, 0, ELT_SIZE);
		arraycopy(p, offset + ELT_SIZE, y, 0, ELT_SIZE);

		elt_square(t, x);
		elt_mul(s, t, x);// s = x^3

		elt_mul(t, x, ec_a);
		elt_add(s, s, t); //s = x^3 + a *x

		elt_add(s, s, ec_b);//s = x^3 + a *x + b

		elt_square(t, y); //t = y^2
		elt_sub(s, s, t); // is s - t = 0?

		hex_dump("S", s, ELT_SIZE);
		hex_dump("T", t, ELT_SIZE);

		return elt_is_zero(s);
	}

	public static void dump_ecc() {
		hex_dump("P", ec_p, ELT_SIZE);
		hex_dump("a", ec_a, ELT_SIZE);
		hex_dump("b", ec_b, ELT_SIZE);
		hex_dump("N", ec_N, BIGNUMBER_SIZE);
		hex_dump("Gx", ec_G.x, ELT_SIZE);
		hex_dump("Gy", ec_G.y, ELT_SIZE);
	}
}
