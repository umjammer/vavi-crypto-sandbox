/*
 * Copyright (c) 2025 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.jstk.asn1;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;


/**
 * ASN1OidTest.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (nsano)
 * @version 0.00 2025-11-27 nsano initial version <br>
 */
class ASN1OidTest {

    @Test
    void test1() throws Exception {
        byte[] bytes = {
                (byte) 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d
        };
        ASN1Oid oid = new ASN1Oid();
        oid.setValue(bytes);
        assertEquals("1.2.840.113549", oid.toString());
        oid.setOid("1.5.8");
        assertEquals("1.5.8", oid.toString());
        oid.setOid("1.2.840.113549.1");
        assertEquals("1.2.840.113549.1", oid.toString());
        oid.setOid("2.5.4.6");
        assertEquals("2.5.4.6", oid.toString());
        oid.setOid("2.5.4.3");
        assertEquals("2.5.4.3", oid.toString());
    }
}
