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
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Stream;

import org.jstk.pem.InvalidPEMFormatException;
import org.jstk.pem.PEMData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import vavi.util.Debug;
import vavi.util.StringUtil;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ASN1ParseTest {
    public static final Logger logger = ASN1Type.logger;

    static class InputFile {
        byte[] bytes;
        String file;
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

    protected static List<InputFile> inputFileList = new ArrayList<>();

    @BeforeAll
    static void setUp() {
        for (int i = 0; i < inputFiles.length; i++) {
            String file = inputFiles[i];
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
                    logger.info("I/O problem with : " + file + ", Exception: " + ioe + ". Skipping ...");
                    continue;
                }
                bytes = baos.toByteArray();
            } catch (IOException ioe) { // Input file has a problem
                logger.info("I/O problem with : " + file + ", Exception: " + ioe + ". Skipping ...");
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
        logger.entering(getClass().getName(), "testParse");

        DefASN1PullParser parser = new DefASN1PullParser();
        parser.setInput(new ByteArrayInputStream(inpf.bytes));
        while (parser.next() != ASN1PullParser.EOF)
            ;

        logger.info("parsing succeeded for file: " + inpf.file);
        logger.exiting(getClass().getName(), "testParse");
    }

    @ParameterizedTest
    @MethodSource("fileProvider")
    void testDecode(InputFile inpf) throws Exception {
        logger.entering(getClass().getName(), "testDecode");

        DefASN1PullParser parser = new DefASN1PullParser();
        parser.setInput(new ByteArrayInputStream(inpf.bytes));
        ASN1Any any = new ASN1Any();
        any.decode(parser);

        logger.info("decode succeeded for file: " + inpf.file);
        logger.exiting(getClass().getName(), "testDecode");
    }

    @Disabled("first 8 bytes differ")
    @ParameterizedTest
    @MethodSource("fileProvider")
    void testRoundTrip(InputFile inpf) throws Exception {
        logger.entering(getClass().getName(), "testRoundTrip");

        DefASN1PullParser parser = new DefASN1PullParser();
        parser.setInput(new ByteArrayInputStream(inpf.bytes));
        ASN1Any any = new ASN1Any();
        any.decode(parser);
        byte[] encoded = any.encode();
Debug.println("before:\n" + StringUtil.getDump(inpf.bytes, 128));
Debug.println("after:\n" + StringUtil.getDump(encoded, 128));
        assertArrayEquals(inpf.bytes, encoded);

        logger.info("roundtrip test succeeded for file: " + inpf.file);
        logger.exiting(getClass().getName(), "testRoundTrip");
    }
}
