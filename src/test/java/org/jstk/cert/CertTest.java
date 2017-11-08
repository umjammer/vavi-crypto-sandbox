/*
 * @(#) $Id: CertTest.java,v 1.1.1.1 2003/10/05 18:39:13 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.cert;

import java.math.BigInteger;

import org.jstk.JSTKUtil;
import org.jstk.asn1.ASN1Boolean;
import org.jstk.asn1.ASN1Integer;
import org.jstk.asn1.ASN1PullParser;
import org.jstk.asn1.ASN1PullParserException;
import org.jstk.asn1.ASN1Seq;
import org.jstk.asn1.DefASN1PullParser;
import org.junit.Test;


public class CertTest {

    @Test
    public void testBasicConstraint() throws ASN1PullParserException, java.io.IOException {
        ASN1Seq basicConstraints = new ASN1Seq();
        ASN1Boolean caFlag = new ASN1Boolean();
        caFlag.setValue(true);
        ASN1Integer pathLen = new ASN1Integer();
        pathLen.setValue(new BigInteger("5"));
        basicConstraints.add(caFlag);
        basicConstraints.add(pathLen);

        byte[] encoded = basicConstraints.encode();
        System.out.println();
        System.out.println("Encoded Basic Constraint (HEX): " + JSTKUtil.hexStringFromBytes(encoded));
        System.out.println();

        System.out.println("Parsed Basic Constraint:");
        ASN1PullParser parser = DefASN1PullParser.getInstance(encoded);
        parser.printParsed(System.out);
    }

    @Test
    public void testCGBasicConstraint() throws ASN1PullParserException, java.io.IOException {

        CertificateGenerator cg = new CertificateGenerator(null, null);
        cg.setBasicConstraints(true, 5);
        byte[] encoded = cg.encodeBasicConstraints();

        System.out.println("Encoded Basic Constraint Extn. (HEX): " + JSTKUtil.hexStringFromBytes(encoded));
        System.out.println();

        System.out.println("Parsed Basic Constraint Extn.:");
        ASN1PullParser parser = DefASN1PullParser.getInstance(encoded);
        parser.printParsed(System.out);
    }
}
