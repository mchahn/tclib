package de.org.mchahn.tclib.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import de.org.mchahn.baselib.util.BytePtr;
import de.org.mchahn.tclib.util.Erasable;
import de.org.mchahn.tclib.util.Testable;

/**
 * Definition of random number generators.
 */
public abstract class Rand implements Testable, Erasable {

    /**
     * Create new random data.
     * @param buf Buffer to store the random bytes.
     * @param ofs Where to start writing in the buffer.
     * @param len Number of bytes to write.
     */
    public abstract void make(byte[] buf, int ofs, int len);

    /**
     * Create new random data.
     * @param bp Pointer to the output area.
     */
    public void make(BytePtr bp) {
        make(bp.buf, bp.ofs, bp.len);
    }

    ///////////////////////////////////////////////////////////////////////////

    private static class Wrapper extends Rand {
        static final int RND_WRD_SZ = 4;    // must be 2^N (N>0, N<31)

        Random random;
        byte[] rndwrd = new byte[RND_WRD_SZ];

        protected Wrapper(Random random) {
            this.random = random;
        }

        @Override
        public void make(byte[] buf, int ofs, int len) {
            final Random random = this.random;
            final byte[] rndwrd = this.rndwrd;

            final int end = ofs + len;

            for (int c = end & ~(RND_WRD_SZ - 1); ofs < c; ofs += RND_WRD_SZ) {
                random.nextBytes(rndwrd);
                System.arraycopy(rndwrd, 0, buf, ofs, RND_WRD_SZ);
            }
            System.arraycopy(rndwrd, 0, buf, ofs, ofs - end);

            // we don't want to cache the leftover random data, since it might
            // become key material and thus should not exist for too long...
        }

        @Override
        public void test() {
            // TODO: could run a chi-square test or something similar
        }

        @Override
        public void erase() {
            Arrays.fill(this.rndwrd, (byte)0);

            // maybe this helps or it doesn't - we can't really tell
            this.random.setSeed(0L);
        }
    }

    /**
     * Wrap a standard framework RNG.
     * @param random The random number generator to wrap.
     * @return Wrapped instance.
     */
    public static Rand wrap(Random random) {
        return new Wrapper(random);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Provides the global secure random number instance. It should be seeded
     * with extra data whenever possible, to provide even better randomness.
     * @return The global secure random number generator. 100% thread-safe too.
     */
    public static Random secure() {
        return _srand;
    }

    private static final SecureRandom _srand = new SecureRandom() {
        @Override
        public synchronized int hashCode() {
            return super.hashCode();
        }
        @Override
        public synchronized boolean equals(Object obj) {
            return super.equals(obj);
        }
        @Override
        protected Object clone() throws CloneNotSupportedException {
            throw new CloneNotSupportedException();
        }
        @Override
        public String toString() {
            return super.toString();
        }
        private static final long serialVersionUID = 2173765181962678519L;
    };
}
