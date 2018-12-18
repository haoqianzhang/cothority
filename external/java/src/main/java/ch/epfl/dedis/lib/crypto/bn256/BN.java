package ch.epfl.dedis.lib.crypto.bn256;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class BN {
    static BigInteger randPosBigInt(Random rnd, BigInteger n) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd);
        } while (r.signum() <= 0 || r.compareTo(n) >= 0);
        return r;
    }

    public static byte[] bigIntegerToBytes(final BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray();
            if(bytes[0] == 0) {
                return Arrays.copyOfRange(bytes, 1, bytes.length);
            }
            return bytes;
        }

    private final static char[] hexArray = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static class PairG1 {
        public BigInteger k;
        public G1 p;
        public PairG1(BigInteger k, G1 p) {
            this.k = k;
            this.p = p;
        }
    }

    public static class PairG2 {
        public BigInteger k;
        public G2 p;
        public PairG2(BigInteger k, G2 p) {
            this.k = k;
            this.p = p;
        }
    }

    public static class G1 {
        CurvePoint p;
        public G1() {
            this.p = new CurvePoint();
        }

        public G1(CurvePoint p) {
            this.p = p;
        }

        public static PairG1 rand(Random rnd) {
            BigInteger k = randPosBigInt(rnd, Constants.order);
            G1 p = new G1().scalarBaseMul(k);
            return new PairG1(k, p);
        }

        public String toString() {
            return "bn256.G1" + this.p.toString();
        }

        public G1 scalarBaseMul(BigInteger k) {
            this.p.mul(CurvePoint.curveGen, k);
            return this;
        }

        public G1 scalarMul(G1 a, BigInteger k) {
            this.p.mul(a.p, k);
            return this;
        }

        public G1 add(G1 a, G1 b) {
            this.p.add(a.p, b.p);
            return this;
        }

        public G1 neg(G1 a) {
            this.p.negative(a.p);
            return this;
        }

        public byte[] marshal() {
            final int numBytes = 256/8;

            if (this.p.isInfinity()) {
                return new byte[numBytes*2];
            }

            this.p.makeAffine();

            byte[] xBytes = bigIntegerToBytes(this.p.x.mod(Constants.p));
            byte[] yBytes = bigIntegerToBytes(this.p.y.mod(Constants.p));

            byte[] ret = new byte[numBytes*2];
            System.arraycopy(xBytes, 0, ret, 1*numBytes-xBytes.length, xBytes.length);
            System.arraycopy(yBytes, 0, ret, 2*numBytes-yBytes.length, yBytes.length);

            return ret;
        }

        public G1 unmarshal(byte[] m) {
            final int numBytes = 256/8;

            if (m.length != 2*numBytes) {
                return null;
            }

            this.p.x = new BigInteger(1, Arrays.copyOfRange(m, 0*numBytes, 1*numBytes));
            this.p.y = new BigInteger(1, Arrays.copyOfRange(m, 1*numBytes, 2*numBytes));

            if (this.p.x.signum() == 0 && this.p.y.signum() == 0) {
                this.p.y = BigInteger.ONE;
                this.p.z = BigInteger.ZERO;
                this.p.t = BigInteger.ZERO;
            } else {
                this.p.z = BigInteger.ONE;
                this.p.t = BigInteger.ONE;
                if (!this.p.isOnCurve())  {
                    return null;
                }
            }

            return this;
        }
    }

    public static class G2 {
        TwistPoint p;
        public G2() {
            this.p = new TwistPoint();
        }

        public G2(TwistPoint p) {
            this.p = p;
        }

        public static PairG2 rand(Random rnd) {
            BigInteger k = randPosBigInt(rnd, Constants.order);
            G2 p = new G2().scalarBaseMul(k);
            return new PairG2(k, p);
        }

        public String toString() {
            return "bn256.G2" + this.p.toString();
        }

        public G2 scalarBaseMul(BigInteger k) {
            this.p.mul(TwistPoint.twistGen, k);
            return this;
        }

        public G2 sclarMul(G2 a, BigInteger k) {
            this.p.mul(a.p, k);
            return this;
        }

        public G2 add(G2 a, G2 b) {
            this.p.add(a.p, b.p);
            return this;
        }

        public byte[] marshal() {
            final int numBytes = 256/8;

            if (this.p.isInfinity()) {
                return new byte[numBytes*4];
            }

            this.p.makeAffine();

            byte[] xxBytes = bigIntegerToBytes(this.p.x.x.mod(Constants.p));
            byte[] xyBytes = bigIntegerToBytes(this.p.x.y.mod(Constants.p));
            byte[] yxBytes = bigIntegerToBytes(this.p.y.x.mod(Constants.p));
            byte[] yyBytes = bigIntegerToBytes(this.p.y.y.mod(Constants.p));

            byte[] ret = new byte[numBytes*4];
            System.arraycopy(xxBytes, 0, ret, 1*numBytes-xxBytes.length, xxBytes.length);
            System.arraycopy(xyBytes, 0, ret, 2*numBytes-xyBytes.length, xyBytes.length);
            System.arraycopy(yxBytes, 0, ret, 3*numBytes-yxBytes.length, yxBytes.length);
            System.arraycopy(yyBytes, 0, ret, 4*numBytes-yyBytes.length, yyBytes.length);

            return ret;
        }

        public G2 unmarshal(byte[] m) {
            final int numBytes = 256 / 8;

            if (m.length != 4*numBytes) {
                return null;
            }

            if (this.p == null) {
                this.p = new TwistPoint();
            }

            this.p.x.x = new BigInteger(1, Arrays.copyOfRange(m, 0*numBytes, 1*numBytes));
            this.p.x.y = new BigInteger(1, Arrays.copyOfRange(m, 1*numBytes, 2*numBytes));
            this.p.y.x = new BigInteger(1, Arrays.copyOfRange(m, 2*numBytes, 3*numBytes));
            this.p.y.y = new BigInteger(1, Arrays.copyOfRange(m, 3*numBytes, 4*numBytes));

            if (this.p.x.x.signum() == 0 && this.p.x.y.signum() == 0 && this.p.y.x.signum() == 0 && this.p.y.y.signum() == 0) {
                this.p.y.setOne();
                this.p.z.setZero();
                this.p.t.setZero();
            } else {
                this.p.z.setOne();
                this.p.t.setOne();

                if (!this.p.isOnCurve()) {
                    return null;
                }
            }

            return this;
        }
    }

    public static class GT {
        GFp12 p;
        public GT() {
            this.p = new GFp12();
        }
        public GT(GFp12 p) {
            this.p = p;
        }
        public String toString() {
            return "bn256.GT" + this.p.toString();
        }
        public GT scalarMul(GT a, BigInteger k) {
            this.p.exp(a.p, k);
            return this;
        }
        public GT add(GT a, GT b) {
            this.p.mul(a.p, b.p);
            return this;
        }
        public GT neg(GT a) {
            this.p.invert(a.p);
            return this;
        }
        public byte[] marshal() {
            this.p.minimal();

            byte[] xxxBytes = bigIntegerToBytes(this.p.x.x.x);
            byte[] xxyBytes = bigIntegerToBytes(this.p.x.x.y);
            byte[] xyxBytes = bigIntegerToBytes(this.p.x.y.x);
            byte[] xyyBytes = bigIntegerToBytes(this.p.x.y.y);
            byte[] xzxBytes = bigIntegerToBytes(this.p.x.z.x);
            byte[] xzyBytes = bigIntegerToBytes(this.p.x.z.y);
            byte[] yxxBytes = bigIntegerToBytes(this.p.y.x.x);
            byte[] yxyBytes = bigIntegerToBytes(this.p.y.x.y);
            byte[] yyxBytes = bigIntegerToBytes(this.p.y.y.x);
            byte[] yyyBytes = bigIntegerToBytes(this.p.y.y.y);
            byte[] yzxBytes = bigIntegerToBytes(this.p.y.z.x);
            byte[] yzyBytes = bigIntegerToBytes(this.p.y.z.y);

            final int numBytes = 256/8;

            byte[] ret = new byte[numBytes*12];
            System.arraycopy(xxxBytes, 0, ret, 1*numBytes-xxxBytes.length, xxxBytes.length);
            System.arraycopy(xxyBytes, 0, ret, 2*numBytes-xxyBytes.length, xxyBytes.length);
            System.arraycopy(xyxBytes, 0, ret, 3*numBytes-xyxBytes.length, xyxBytes.length);
            System.arraycopy(xyyBytes, 0, ret, 4*numBytes-xyyBytes.length, xyyBytes.length);
            System.arraycopy(xzxBytes, 0, ret, 5*numBytes-xzxBytes.length, xzxBytes.length);
            System.arraycopy(xzyBytes, 0, ret, 6*numBytes-xzyBytes.length, xzyBytes.length);
            System.arraycopy(yxxBytes, 0, ret, 7*numBytes-yxxBytes.length, yxxBytes.length);
            System.arraycopy(yxyBytes, 0, ret, 8*numBytes-yxyBytes.length, yxyBytes.length);
            System.arraycopy(yyxBytes, 0, ret, 9*numBytes-yyxBytes.length, yyxBytes.length);
            System.arraycopy(yyyBytes, 0, ret, 10*numBytes-yyyBytes.length, yyyBytes.length);
            System.arraycopy(yzxBytes, 0, ret, 11*numBytes-yzxBytes.length, yzxBytes.length);
            System.arraycopy(yzyBytes, 0, ret, 12*numBytes-yzyBytes.length, yzyBytes.length);

            return ret;
        }
        public GT unmarshal(byte[] m) {
            final int numBytes = 256 / 8;

            if (m.length != 12*numBytes) {
                return null;
            }

            if (this.p == null) {
                this.p = new GFp12();
            }

            this.p.x.x.x = new BigInteger(1, Arrays.copyOfRange(m,0*numBytes, 1*numBytes));
            this.p.x.x.y = new BigInteger(1, Arrays.copyOfRange(m,1*numBytes, 2*numBytes));
            this.p.x.y.x = new BigInteger(1, Arrays.copyOfRange(m,2*numBytes, 3*numBytes));
            this.p.x.y.y = new BigInteger(1, Arrays.copyOfRange(m,3*numBytes, 4*numBytes));
            this.p.x.z.x = new BigInteger(1, Arrays.copyOfRange(m,4*numBytes, 5*numBytes));
            this.p.x.z.y = new BigInteger(1, Arrays.copyOfRange(m,5*numBytes, 6*numBytes));
            this.p.y.x.x = new BigInteger(1, Arrays.copyOfRange(m,6*numBytes, 7*numBytes));
            this.p.y.x.y = new BigInteger(1, Arrays.copyOfRange(m,7*numBytes, 8*numBytes));
            this.p.y.y.x = new BigInteger(1, Arrays.copyOfRange(m,8*numBytes, 9*numBytes));
            this.p.y.y.y = new BigInteger(1, Arrays.copyOfRange(m,9*numBytes, 10*numBytes));
            this.p.y.z.x = new BigInteger(1, Arrays.copyOfRange(m,10*numBytes, 11*numBytes));
            this.p.y.z.y = new BigInteger(1, Arrays.copyOfRange(m,11*numBytes, 12*numBytes));

            return this;

        }
    }

    public static GT pair(G1 g1, G2 g2) {
        return new GT(OptAte.optimalAte(g2.p, g1.p));
    }
}
