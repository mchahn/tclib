package de.org.mchahn.tclib.crypto;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class BlockCipherTest {

    @Test
    public void test0() {
        BlockCipher bc = new BlockCipher() {
            @Override
            public String name() {
                return null;
            }
            @Override
            public void erase() {
            }
            @Override
            public void test() throws Throwable {
            }
            @Override
            public int blockSize() {
                return 0;
            }
            @Override
            public int keySize() {
                return 0;
            }
            @Override
            public void processBlock(byte[] in, int ofs_i, byte[] out, int ofs_o) {
            }
            @Override
            public Object clone() {
                throw new AssertionError();
            }
        };
        bc.initialize(BlockCipher.Mode.ENCRYPT, null,  0);
        assertTrue(BlockCipher.Mode.ENCRYPT == bc.mode());
    }
}
