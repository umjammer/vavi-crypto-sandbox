/*
 * @(#) $Id: ASN1Any.java,v 1.1.1.1 2003/10/05 18:39:11 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.asn1;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;

import static java.lang.System.getLogger;


/**
 * ASN1Any.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 2005/03/17 nsano initial version <br>
 */
public class ASN1Any extends ASN1Type {

    private static final Logger logger = getLogger(ASN1Any.class.getName());

    /** */
    private ASN1Type instance = null;

    /** */
    public ASN1Any() {
        super(UNIVERSAL, NONE, ANY, ANY);
    }

    /** */
    public ASN1Any(byte tagClass, int taggingMethod, int tagNumber) {
        super(tagClass, taggingMethod, tagNumber, ANY);
    }

    /** */
    public void decode(ASN1PullParser parser) throws ASN1PullParserException, IOException {
        logger.log(Level.TRACE,  getClass().getName() + ": decode");
        int event = parser.next();
        logger.log(Level.DEBUG, "[ASN1Any.decode()] event = " + event + ", off = " + parser.getOffset() + ", len = " + parser.getLength());
        instance = createASN1Type(event, parser.getTagClass());
        logger.log(Level.DEBUG, "unknown type: " + instance.getClass() + ", " + parser.getTagClass());
        if (instance instanceof ASN1Any) {
            instance.setTagClass(parser.getTagClass());
            instance.setTagNumber(parser.getTagNumber());
            instance.setConsMask(parser.getConsMask());
            instance.setValue(parser.getContent());
            instance.setLength(parser.getLength());
            logger.log(Level.DEBUG, "unknown type: " + instance);
        } else {
            parser.prev(); // backup
            instance.decode(parser);
            logger.log(Level.DEBUG, "known type: " + instance);
        }
        logger.log(Level.TRACE,  getClass().getName() + ": decode");
    }

    /** */
    public byte[] encode() {
        logger.log(Level.TRACE,  getClass().getName() + ": encode");
        byte[] bytes;
        if (instance == null) {
            bytes = encode1();
        } else {
            bytes = instance.encode();
        }
        logger.log(Level.TRACE,  getClass().getName() + ": encode");
        return bytes;
    }

    /** */
    public void setInstance(ASN1Type instance) {
        this.instance = instance;
    }

    /** */
    public static ASN1Type createASN1Type(int event, byte tagClass) {
        if (tagClass != UNIVERSAL) {
            return new ASN1Any();
        }

        return switch (event) {
            case ASN1PullParser.BOOLEAN -> new ASN1Boolean();
            case ASN1PullParser.INTEGER -> new ASN1Integer();
            case ASN1PullParser.BIT_STRING -> new ASN1BitString();
            case ASN1PullParser.OCTET_STRING -> new ASN1OctetString();
            case ASN1PullParser.NULL -> new ASN1Null();
            case ASN1PullParser.OID -> new ASN1Oid();
            case ASN1PullParser.START_SEQ -> new ASN1Seq();
            case ASN1PullParser.START_SET -> new ASN1Set();
            case ASN1PullParser.PrintableString -> new ASN1PrintableString();
            case ASN1PullParser.IA5String -> new ASN1IA5String();
            case ASN1PullParser.UTCTime -> new ASN1UTCTime();
            default -> new ASN1Any();
        };
    }

    /** */
    public String toString() {
        if (instance == null) {
            return null;
        }
        return instance.toString();
    }
}
