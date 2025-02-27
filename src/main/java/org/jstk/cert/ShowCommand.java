/*
 * @(#) $Id: ShowCommand.java,v 1.1.1.1 2003/10/05 18:39:14 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.cert;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jstk.JSTKArgs;
import org.jstk.JSTKCommandAdapter;
import org.jstk.JSTKException;
import org.jstk.JSTKOptions;
import org.jstk.JSTKResult;

import static java.lang.System.getLogger;


public class ShowCommand extends JSTKCommandAdapter {

    private static final Logger logger = getLogger(ShowCommand.class.getName());

    private static final Map<String, String> defaults = new HashMap<>();

    static {
        // defaults.put("infile", "my.cer");
    }

    public String briefDescription() {
        String briefDesc = "display contents of a PKI file";
        return briefDesc;
    }

    public String optionsDescription() {
        String optionsDesc = "  -infile <infile>  : File having the PKI material ( cert, certpath, CRL, ...).\n" + defaults.get("infile") + "]\n";
        return optionsDesc;
    }

    public String[] useForms() {
        String[] useForms = {
            "-infile <infile>"
        };
        return useForms;
    }

    public String[] sampleUses() {
        String[] sampleUses = {
            "-infile test.cer"
        };
        return sampleUses;
    }

    public void formatX509Certificate(X509Certificate cert, StringBuffer sb, String indent) {
        sb.append(indent).append("Certificate:\n");
        sb.append(indent).append("  Data:\n");
        sb.append(indent).append("    Version: ").append(cert.getVersion()).append("\n");
        sb.append(indent).append("    Serial Number: ").append(cert.getSerialNumber()).append("\n");
        sb.append(indent).append("    Signature Algorithm: ").append(cert.getSigAlgName()).append("\n");
        sb.append(indent).append("    Issuer: ").append(cert.getIssuerX500Principal()).append("\n");
        sb.append(indent).append("    Validity:\n");
        sb.append(indent).append("      Not Before: ").append(cert.getNotBefore()).append(" \n");
        sb.append(indent).append("      Not After: ").append(cert.getNotAfter()).append(" \n");
        sb.append(indent).append("    Subject: ").append(cert.getSubjectX500Principal()).append("\n");
        sb.append(indent).append("    Extensions: \n");

        sb.append(indent).append("      X509v3 Basic Constraints:\n");
        int pathLen = cert.getBasicConstraints();
        if (pathLen != -1) // Not a CA
            sb.append(indent).append("        CA: TRUE, pathLen: ").append(pathLen).append("\n");
        else
            sb.append(indent).append("        CA: FALSE\n");

        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            KeyUsage ku = new KeyUsage(keyUsage);
            sb.append(indent).append("      Key Usage: ").append(ku.getKeyUsageString()).append("\n");
        }

        List<String> list = null;
        try {
            list = cert.getExtendedKeyUsage();
        } catch (CertificateParsingException cpe) {
        }

        if (list != null) {
            sb.append(indent).append("      Extended Key Usage:");
            for (String s : list) {
                sb.append(" ");
                sb.append(s);
            }
            sb.append("\n");
        }
    }

    public void formatCertPath(CertPath cp, StringBuffer sb) {
        List<? extends Certificate> list = cp.getCertificates();
        Iterator<? extends Certificate> li = list.iterator();
        sb.append("CertPath:\n");
        int index = 0;
        while (li.hasNext()) {
            sb.append("CertPath Component: ").append(index).append("\n");
            X509Certificate cert = (X509Certificate) li.next();
            formatX509Certificate(cert, sb, "  ");
            ++index;
        }
    }

    public void formatX509CRL(X509CRL crl, StringBuffer sb) {
        sb.append("CRL:\n");
        sb.append("  Version: ").append(crl.getVersion()).append("\n");
        sb.append("  Signature Algorithm: ").append(crl.getSigAlgName()).append("\n");
        sb.append("  Issuer: ").append(crl.getIssuerX500Principal()).append("\n");
        sb.append("  This Update: ").append(crl.getThisUpdate()).append("\n");
        sb.append("  Next Update: ").append(crl.getNextUpdate()).append("\n");

        Set<? extends X509CRLEntry> revokedCerts = crl.getRevokedCertificates();
        if (revokedCerts == null)
            return;
        Iterator<? extends X509CRLEntry> itr = revokedCerts.iterator();
        int index = 0;
        while (itr.hasNext()) {
            formatX509CRLEntry(itr.next(), sb, index);
            ++index;
        }
    }

    public void formatX509CRLEntry(X509CRLEntry crlEntry, StringBuffer sb, int index) {
        sb.append("  CRLEntry[").append(index).append("]:\n");
        sb.append("    Serial Number: ").append(crlEntry.getSerialNumber()).append("\n");
        sb.append("    Revocation Date: ").append(crlEntry.getRevocationDate()).append("\n");
    }

    public Object execute(JSTKArgs args) throws JSTKException {
        try {
            args.setDefaults(defaults);
            String infile = args.get("infile");
            if (infile == null) {
                return new JSTKResult(null, false, "No input file. Specify -infile option.");
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            StringBuffer sb = new StringBuffer();

            File file = new File(infile);
            int bufsize = (int) file.length() + 1024; // Added 1024 for extra safety.
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(infile), bufsize);
            bis.mark(bufsize);

            try {
                Certificate cert = cf.generateCertificate(bis);
                formatX509Certificate((X509Certificate) cert, sb, "");
                return new JSTKResult(null, true, sb.toString());
            } catch (CertificateException ce) {
                logger.log(Level.DEBUG, "Cannot parse input as a Certificate");
                logger.log(Level.DEBUG, "Not a Certificate: " + ce);
            } // Fall through.

            bis.reset();
            try {
                CertPath cp = cf.generateCertPath(bis, "PkiPath");
                formatCertPath(cp, sb);
                return new JSTKResult(null, true, sb.toString());
            } catch (CertificateException ce) {
                logger.log(Level.DEBUG, "Cannot parse input as a PkiPath Cert Path");
                logger.log(Level.DEBUG, "Not a PkiPath Cert Path: " + ce);
            } // Fall through.

            bis.reset();
            try {
                CertPath cp = cf.generateCertPath(bis, "PKCS7");
                formatCertPath(cp, sb);
                return new JSTKResult(null, true, sb.toString());
            } catch (CertificateException ce) {
                logger.log(Level.DEBUG, "Cannot parse input as a PKCS7 Cert Path");
                logger.log(Level.DEBUG, "Not a PKCS7 Cert Path: " + ce);
            } // Fall through.

            bis.reset();
            try {
                X509CRL crl = (X509CRL) cf.generateCRL(bis);
                formatX509CRL(crl, sb);
                return new JSTKResult(null, true, sb.toString());
            } catch (CRLException crle) {
                logger.log(Level.DEBUG, "Cannot parse input as a CRL");
                logger.log(Level.DEBUG, "Not a CRL: " + crle);
            } // Fall through.

            return new JSTKResult(null, false, "Unknown format");
        } catch (Exception exc) {
            throw new JSTKException("ShowCommand execution failed", exc);
        }
    }

    public static void main(String[] args) throws Exception {
        JSTKOptions opts = new JSTKOptions();
        opts.parse(args, 0);
        ShowCommand showCmd = new ShowCommand();
        JSTKResult result = (JSTKResult) showCmd.execute(opts);
        System.out.println(result.getText());
        System.exit(result.isSuccess() ? 0 : 1);
    }
}
