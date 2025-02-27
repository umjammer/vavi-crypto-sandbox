/*
 * @(#) $Id: ASN1PullParser.java,v 1.1.1.1 2003/10/05 18:39:12 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;


/**
 * ASN1PullParser.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050317 nsano initial version <br>
 */
public interface ASN1PullParser {
    /** */
    int ANY = 0;

    /** */
    int BOOLEAN = 1;

    /** */
    int INTEGER = 2;

    /** */
    int BIT_STRING = 3;

    /** */
    int OCTET_STRING = 4;

    /** */
    int NULL = 5;

    /** */
    int OID = 6;

    /** */
    int START_SEQ = 7;

    /** */
    int END_SEQ = 8;

    /** */
    int START_SET = 9;

    /** */
    int END_SET = 10;

    /** */
    int SEQ = 16;

    /** */
    int SET = 17;

    /** */
    int PrintableString = 19;

    /** */
    int T61String = 20;

    /** */
    int IA5String = 22;

    /** */
    int UTCTime = 23;

    /** */
    int EOF = -1;

    /** */
    int UNKNOWN = -2;

    /** */
    byte CLASSBITS = (byte) 0xc0;

    /** */
    byte TAGBITS = 0x1f;

    /** */
    int next() throws ASN1PullParserException, IOException;

    /** */
    void prev() throws ASN1PullParserException;

    /** */
    int getLength();

    /** */
    int getOffset();

    /** */
    byte[] getContent();

    /** */
    int getInteger();

    /** */
    int getTagNumber();

    /** */
    byte getTagClass();

    /** */
    byte getConsMask();

    /** */
    void setInput(InputStream is);

    /** */
    void printParsed(PrintStream ps) throws IOException, ASN1PullParserException;
}
