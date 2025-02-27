/*
 * @(#) $Id: Version.java,v 1.1.1.1 2003/10/05 18:39:21 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.pki;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.io.IOException;
import org.jstk.asn1.*;

import static java.lang.System.getLogger;


/*
 * Version ::= INTEGER { v1(0), v2(1), v3(2) }
 */
public class Version extends ASN1Type {

    private static final Logger logger = getLogger(Version.class.getName());

    private final ASN1Integer version = new ASN1Integer();

    public Version(byte tagClass, int taggingMethod, int tagNumber) {
        super(tagClass, taggingMethod, tagNumber, 0);
        consMask = CONSTRUCTED;
        version.setDefaultValue(new BigInteger("0"));
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public void decode(ASN1PullParser parser) throws ASN1PullParserException, IOException {
        int event = parser.next();

        if ((event != tagNumber) || (parser.getTagClass() != tagClass)) {
            parser.prev(); // skip
            return;
        }
        version.decode(parser);
    }

    public byte[] encode() {
        logger.log(Level.TRACE,  getClass().getName() + ": encode");
        byte[] bytes = version.encode();
        if (bytes != null) {
            value = bytes;
            length = bytes.length;
            bytes = encode1();
            logger.log(Level.DEBUG, "non-default version encoded");
        } else {
            logger.log(Level.DEBUG, "default version NOT encoded");
        }
        logger.log(Level.TRACE,  getClass().getName() + ": encode");
        return bytes;
    }

    public String toString() {
        return "Version-INTEGER(" + version + ")";
    }
}
