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

import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;


public class SHA1 {

    private static final Logger logger = Logger.getLogger(SHA1.class.getName());

    public SHA1() {
    }

    public byte[] doSHA1(byte[] bytes, int length) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(bytes, 0, length);
            byte[] sha1Hash = md.digest();
            return sha1Hash;
        } catch (Exception e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            return null;
        }
    }
}