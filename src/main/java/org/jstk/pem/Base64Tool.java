/*
 * @(#) $Id: Base64Tool.java,v 1.1.1.1 2003/10/05 18:39:20 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.pem;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.util.logging.Logger;

import org.jstk.JSTKAbstractTool;
import org.jstk.JSTKArgs;
import org.jstk.JSTKCommandAdapter;
import org.jstk.JSTKException;
import org.jstk.JSTKResult;


public class Base64Tool extends JSTKAbstractTool {

    static class EncodeCommand extends JSTKCommandAdapter {

        @Override
        public String briefDescription() {
            String briefDesc = "encodes input data to base64 format";
            return briefDesc;
        }

        @Override
        public String optionsDescription() {
            String optionsDesc = """
                      -infile <infile>  : File to be base64 encoded.
                      -intext <text>    : Text to be base64 encoded.
                      -outfile <outfile>: Output file to store base64 encoded data.
                    """;
            return optionsDesc;
        }

        @Override
        public String[] useForms() {
            String[] useForms = {
                    "(-infile <infile> | -intext <text>) [-outfile <outfile>]"
            };
            return useForms;
        }

        @Override
        public String[] sampleUses() {
            String[] sampleUses = {
                    "-infile test.cer", "-infile test.cer -outfile test.pem", "-intext \"Hello, World!\""
            };
            return sampleUses;
        }

        @Override
        public Object execute(JSTKArgs args) throws JSTKException {
            try {
                String intext;
                PEMData pemData;
                String msg;

                String infile = args.get("infile");
                String outfile = args.get("outfile");
                if (infile == null) {
                    intext = args.get("intext");
                    if (intext == null)
                        return new JSTKResult(null, false, "No input data. Specify -infile  or -intext option.");
                    pemData = new PEMData(intext.getBytes());
                } else {
                    BufferedInputStream bis = new BufferedInputStream(new FileInputStream(infile));
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buf = new byte[1024];
                    int n;
                    while ((n = bis.read(buf, 0, buf.length)) > 0) {
                        baos.write(buf, 0, n);
                    }
                    bis.close();
                    pemData = new PEMData(baos.toByteArray());
                }
                String text = pemData.encode();
                if (outfile != null) {
                    FileOutputStream fos = new FileOutputStream(outfile);
                    fos.write(text.getBytes());
                    fos.close();
                    msg = "base64 encoded data written to file: " + outfile;
                } else {
                    msg = "base64 encoded data: " + text;
                }
                return new JSTKResult(null, true, msg);
            } catch (Exception exc) {
                throw new JSTKException("EncodeCommand execution failed", exc);
            }
        }
    }

    static class DecodeCommand extends JSTKCommandAdapter {

        @Override
        public String briefDescription() {
            String briefDesc = "decodes base64 input data";
            return briefDesc;
        }

        @Override
        public String optionsDescription() {
            String optionsDesc = """
                      -infile <infile>  : File hvaing base64 encoded data.
                      -intext <text>    : Text in base64 format.
                      -outfile <outfile>: Output file to store decoded data.
                    """;
            return optionsDesc;
        }

        @Override
        public String[] useForms() {
            String[] useForms = {
                    "(-infile <infile> | -intext <text>) [-outfile <outfile>]"
            };
            return useForms;
        }

        @Override
        public String[] sampleUses() {
            String[] sampleUses = {
                    "-infile test.pem", "-infile test.pem -outfile test.cer", "-intext SGVsbG8sIFdvcmxkIQ=="
            };
            return sampleUses;
        }

        @Override
        public Object execute(JSTKArgs args) throws JSTKException {
            try {
                String intext;
                PEMData pemData;
                String msg;

                String infile = args.get("infile");
                String outfile = args.get("outfile");
                if (infile == null) {
                    intext = args.get("intext");
                    if (intext == null)
                        return new JSTKResult(null, false, "No input data. Specify -infile  or -intext option.");
                    pemData = new PEMData(intext);
                } else {
                    BufferedReader reader = new BufferedReader(new FileReader(infile));
                    pemData = new PEMData(reader);
                }
                byte[] raw = pemData.decode();
                if (outfile != null) {
                    FileOutputStream fos = new FileOutputStream(outfile);
                    fos.write(raw);
                    fos.close();
                    msg = "decoded data written to file: " + outfile;
                } else {
                    msg = "decoded data: " + new String(raw);
                }
                return new JSTKResult(null, true, msg);
            } catch (Exception exc) {
                throw new JSTKException("DecodeCommand execution failed", exc);
            }
        }
    }

    public static final Logger logger = Logger.getLogger("org.jstk.pem");

    static {
        cmds.put("encode", new EncodeCommand());
        cmds.put("decode", new DecodeCommand());
    }

    @Override
    public String progName() {
        String progName = System.getProperty("org.jstk.pem.progname");
        if (progName == null)
            progName = "java org.jstk.pem.Base64Tool";

        return progName;
    }

    @Override
    public String briefDescription() {
        return "A base64 conversion tool";
    }

    public static void main(String[] args) throws Exception {
        Base64Tool b64t = new Base64Tool();
        System.exit(b64t.execute(args));
    }
}
