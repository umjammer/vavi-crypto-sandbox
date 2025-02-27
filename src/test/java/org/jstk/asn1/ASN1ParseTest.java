/*
 * @(#) $Id: ASN1ParseTest.java,v 1.1.1.1 2003/10/05 18:39:12 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.asn1;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.jstk.pem.InvalidPEMFormatException;
import org.jstk.pem.PEMData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import vavi.util.Debug;
import vavi.util.StringUtil;

import static java.lang.System.getLogger;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;


public class ASN1ParseTest {

    private static final Logger logger = getLogger(ASN1ParseTest.class.getName());

    static class InputFile {
        final byte[] bytes;
        final String file;
        InputFile(byte[] bytes, String file) {
            this.bytes = bytes;
            this.file = file;
        }
        @Override public String toString() {
            return file;
        }
    }

    protected static final String[] inputFiles = new String[] {
        "data/test1.csr", "data/test.crt", "data/test2.pem"
    };

    protected static final List<InputFile> inputFileList = new ArrayList<>();

    @BeforeAll
    static void setUp() {
        for (String file : inputFiles) {
            byte[] bytes = null;
            try { // Try PEM format
                BufferedReader reader = new BufferedReader(new InputStreamReader(ASN1ParseTest.class.getResourceAsStream("/" + file)));
                PEMData x = new PEMData(reader);
                bytes = x.decode();
            } catch (InvalidPEMFormatException exc) { // Assume DER format
                ByteArrayOutputStream baos = null;
                try {
                    FileInputStream is = new FileInputStream(file);
                    baos = new ByteArrayOutputStream();
                    byte[] buf = new byte[1024];
                    int n;
                    while ((n = is.read(buf)) > 0)
                        baos.write(buf, 0, n);
                    is.close();
                } catch (IOException ioe) { // Input file has a problem
                    logger.log(Level.INFO, "I/O problem with : " + file + ", Exception: " + ioe + ". Skipping ...");
                    continue;
                }
                bytes = baos.toByteArray();
            } catch (IOException ioe) { // Input file has a problem
                logger.log(Level.INFO, "I/O problem with : " + file + ", Exception: " + ioe + ". Skipping ...");
                continue;
            }
            inputFileList.add(new InputFile(bytes, file));
        }
    }

    static Stream<InputFile> fileProvider() {
        return inputFileList.stream();
    }

    @ParameterizedTest
    @MethodSource("fileProvider")
    void testParse(InputFile inpf) throws Exception {
        logger.log(Level.TRACE, getClass().getName() + ": testParse");

        DefASN1PullParser parser = new DefASN1PullParser();
        parser.setInput(new ByteArrayInputStream(inpf.bytes));
        while (parser.next() != ASN1PullParser.EOF)
            ;

        logger.log(Level.INFO, "parsing succeeded for file: " + inpf.file);
        logger.log(Level.TRACE, getClass().getName() + ": testParse");
    }

    @ParameterizedTest
    @MethodSource("fileProvider")
    void testDecode(InputFile inpf) throws Exception {
        logger.log(Level.TRACE, getClass().getName() + ": testDecode");

        DefASN1PullParser parser = new DefASN1PullParser();
        parser.setInput(new ByteArrayInputStream(inpf.bytes));
        ASN1Any any = new ASN1Any();
        any.decode(parser);

        logger.log(Level.INFO, "decode succeeded for file: " + inpf.file);
        logger.log(Level.TRACE, getClass().getName() + ": testDecode");
    }

    @Disabled("first 8 bytes differ")
    @ParameterizedTest
    @MethodSource("fileProvider")
    void testRoundTrip(InputFile inpf) throws Exception {
        logger.log(Level.TRACE, getClass().getName() + ": testRoundTrip");

        DefASN1PullParser parser = new DefASN1PullParser();
        parser.setInput(new ByteArrayInputStream(inpf.bytes));
        ASN1Any any = new ASN1Any();
        any.decode(parser);
        byte[] encoded = any.encode();
Debug.println("before:\n" + StringUtil.getDump(inpf.bytes, 128));
Debug.println("after:\n" + StringUtil.getDump(encoded, 128));
        assertArrayEquals(inpf.bytes, encoded);

        logger.log(Level.INFO, "roundtrip test succeeded for file: " + inpf.file);
        logger.log(Level.TRACE, getClass().getName() + ": testRoundTrip");
    }
}
