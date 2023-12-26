package de.org.mchahn.tclib;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import de.org.mchahn.baselib.io.BlockDeviceImpl;
import de.org.mchahn.baselib.util.BytePtr;
import de.org.mchahn.baselib.util.MiscUtils;
import de.org.mchahn.baselib.test.util.TestUtils;
import de.org.mchahn.tclib.container.Header;
import de.org.mchahn.tclib.container.Volume;
import de.org.mchahn.tclib.crypto.Rand;
import de.org.mchahn.tclib.crypto.Registry;
import de.org.mchahn.tclib.util.Key;
import de.org.mchahn.tclib.util.TCLibException;

public class TCBlockDeviceTest {
    static final int BLOCK_SZ = 512;

    @Before
    public void setup() throws Exception {
        Registry.setup(true);
    }

    @Test
    public void testAvailability() throws Exception {
        String[] names = Registry._blockCiphers.names();
        assertTrue(1 == names.length);
        for (String name : names) assertTrue(null != name && 0 < name.length());

        names = Registry._hashFunctions.names();
        assertTrue(1 < names.length);
        for (String name : names) assertTrue(null != name && 0 < name.length());
    }

    @Test
    public void test0() throws Exception {
        for (final String hashAlgo : new String[] { "RIPEMD-160", "SHA-512" }) {
        for (final long vsz : new long[] { 0, 1, 8, 512, 6543, 50005 }) {

            final long csz = Volume.sizeToContainerSize(vsz);

            BlockDeviceImpl.MemoryBlockDevice mbdev = new
            BlockDeviceImpl.MemoryBlockDevice(BLOCK_SZ, csz, false, false);

            Random rnd = new Random(0x1ac0ffee);

            TCBlockDevice tcbdev = new TCBlockDevice(
                    mbdev,
                    new Key.ByteArray("notyours".getBytes()),
                    hashAlgo,
                    "AES256",
                    false,
                    Rand.wrap(rnd));

            final int[] ridxs = MiscUtils.uniqueRandomIndexes((int)vsz, rnd);

            final byte[] block = new byte[1 + BLOCK_SZ + 1];
            block[0]                = (byte)0xef;
            block[block.length - 1] = (byte)0xfe;

            for (int ridx : ridxs) {
                Arrays.fill(block, 1, block.length - 1, (byte)ridx);
                tcbdev.write(ridx, block, 1);
            }

            tcbdev.close(false);

            final BytePtr bpblk = new BytePtr(block, 1, BLOCK_SZ);
            byte[] mbuf = mbdev.buffer();
            byte[] mbufBak = mbuf.clone();

            for (int i = 0; i < 3; i++) {
                if (1 == i) Arrays.fill(mbuf, 0                        , Header.SIZE, (byte)0xab);
                if (2 == i) Arrays.fill(mbuf, mbuf.length - Header.SIZE, mbuf.length, (byte)0xcd);

                try {
                    tcbdev = new TCBlockDevice(
                            mbdev,
                            new Key.ByteArray("notyours".getBytes()),
                            hashAlgo,
                            "AES256",
                            false);
                }
                catch (TCLibException tle) {
                    assertEquals(2, i);
                    continue;
                }
                assertTrue(0 == i || tcbdev.usedBackupHeader);

                for (int ridx : ridxs) {
                    tcbdev.read(ridx, block, 1);
                    assertTrue((byte)0xef == block[0]);
                    assertTrue((byte)0xfe == block[block.length - 1]);
                    assertTrue(TestUtils.checkFill(bpblk, (byte)ridx));
                }
                tcbdev.close(false);
            }

            mbdev = new BlockDeviceImpl.MemoryBlockDevice(BLOCK_SZ, mbufBak, false, false);
            mbuf = mbdev.buffer();
            for (int i = 0; i < 4; i++) {
                final boolean trybakhdr = 1 < i;
                if (1 == i) Arrays.fill(mbuf, 0                        , Header.SIZE, (byte)0xab);
                if (3 == i) Arrays.fill(mbuf, mbuf.length - Header.SIZE, mbuf.length, (byte)0xcd);

                final TCReader tcrdr;
                try {
                    tcrdr = new TCReader(
                        mbdev,
                        new Key.ByteArray("notyours".getBytes()),
                        trybakhdr,
                        false);
                }
                catch (TCLibException tle) {
                    assertEquals(1, 1 & i);
                    continue;
                }

                for (int ridx : ridxs) {
                    tcrdr.read(ridx, block, 1);
                    assertTrue((byte)0xef == block[0]);
                    assertTrue((byte)0xfe == block[block.length - 1]);
                    assertTrue(TestUtils.checkFill(bpblk, (byte)ridx));
                }

                tcrdr.close(false);
            }
        } }
        return;
    }
}
