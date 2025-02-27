/*
 * @(#) $Id: TBSCertificate.java,v 1.1.1.1 2003/10/05 18:39:21 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.pki;

import org.jstk.asn1.ASN1BitString;
import org.jstk.asn1.ASN1Explicit;
import org.jstk.asn1.ASN1Integer;
import org.jstk.asn1.ASN1Seq;


/*
 * TBSCertificate ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, serialNumber INTEGER, signature AlgorithmIdentifier,
 * issuer Name, validity Validity, subject Name, subjectPublicKeyInfo SubjectPublicKeyInfo issuerUniqueIdentifier [1] IMPLICIT
 * UniqueIdentifier OPTIONAL, subjectUniqueIdentifier [2] IMPLICIT UniqueIdentifier OPTIONAL, extensions [3] EXPLICIT Extensions
 * OPTIONAL }
 */
public class TBSCertificate extends ASN1Seq {
    private final Version version = new Version(CONTEXT, EXPLICIT, 0);

    private final ASN1Integer serialNumber = new ASN1Integer();

    private final AlgorithmIdentifier algorithm = new AlgorithmIdentifier();

    private final Name issuer = new Name();

    private final Validity validity = new Validity();

    private final Name subject = new Name();

    private final SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo();

    private final ASN1BitString issuerUniqueID = new ASN1BitString(CONTEXT, IMPLICIT, 1);

    private final ASN1BitString subjectUniqueID = new ASN1BitString(CONTEXT, IMPLICIT, 2);

    /*
     * private Extensions extensions = new Extensions(CONTEXT, EXPLICIT, 3);
     */
    private final ASN1Explicit extensions = new ASN1Explicit(CONTEXT, EXPLICIT, 3);

    public TBSCertificate() {
        super();
        issuerUniqueID.setOptional(true);
        subjectUniqueID.setOptional(true);
        extensions.setOptional(true);

        add(version);
        add(serialNumber);
        add(algorithm);
        add(issuer);
        add(validity);
        add(subject);
        add(publicKeyInfo);
        add(issuerUniqueID);
        add(subjectUniqueID);
        add(extensions);
    }

    public Version getVersion() {
        return version;
    }

    public ASN1Integer getSerialNumber() {
        return serialNumber;
    }

    public AlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public Name getIssuer() {
        return issuer;
    }

    public Validity getValidity() {
        return validity;
    }

    public Name getSubject() {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return publicKeyInfo;
    }

    public ASN1Explicit getExtensions() {
        return extensions;
    }

    public String toString() {
        String sb = "TBSCertificate-SEQ(" + version.toString() + ", " +
                serialNumber.toString() + ", " + algorithm.toString() +
                ", " + issuer.toString() + ", " + validity.toString() +
                ", " + subject.toString() + ", " + publicKeyInfo.toString() + extensions.toString() + ")";
        return sb;
    }
}
