/*
 * This file is part of jpcsp.
 *
 * Jpcsp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Jpcsp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Jpcsp.  If not, see <http://www.gnu.org/licenses/>.
 */

package jpcsp.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.Test;
import vavi.util.Debug;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;


public class KirkTest {

    private static final byte[] amseed = {
            (byte) 'A', (byte) 'M', (byte) 'C', (byte) 'T', (byte) 'R',
            (byte) 'L', (byte) 'S', (byte) 'E', (byte) 'E', (byte) 'D',
            (byte) 'J', (byte) 'P', (byte) 'C', (byte) 'S', (byte) 'P',
            (byte) '0', (byte) '0', (byte) '0', (byte) '0', (byte) '0'
    };

    @Test
    public void testSha1() throws Exception {
        // Start the KIRK engine with a dummy seed
        KIRK kirk = new KIRK(amseed, 0x14);

        ByteBuffer inp = ByteBuffer.wrap(new byte[] {
                // Size
                0x20, 0x00, 0x00, 0x00,
                // Data
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        }).order(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer out = ByteBuffer.allocate(0x14);
Debug.println("inp.limit: " + inp.limit());
        int result = kirk.hleUtilsBufferCopyWithRange(out, out.limit(), inp, inp.limit(), KIRK.PSP_KIRK_CMD_SHA1_HASH);

        assertEquals(0, result);

        assertArrayEquals(new byte[] {
                        (byte) 0xDE, (byte) 0x8A, (byte) 0x84, 0x7B, (byte) 0xFF, (byte) 0x8C, 0x34, 0x3D, 0x69, (byte) 0xB8, 0x53, (byte) 0xA2,
                        0x15, (byte) 0xE6, (byte) (byte) 0xEE, 0x77, 0x5E, (byte) 0xF2, (byte) 0xEF, (byte) 0x96
                }, out.array());
    }
}
