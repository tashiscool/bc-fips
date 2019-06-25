package org.bouncycastle.jcajce.provider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.util.io.Streams;

/**
 * class for dealing with X509 certificates.
 * <p>
 * At the moment this will deal with "-----BEGIN CERTIFICATE-----" to "-----END CERTIFICATE-----"
 * base 64 encoded certs, as well as the BER binaries of certificates and some classes of PKCS#7
 * objects.
 */
class CertificateFactory
    extends CertificateFactorySpi
{
    private static final PEMUtil PEM_CERT_PARSER = new PEMUtil("CERTIFICATE");
    private static final PEMUtil PEM_CRL_PARSER = new PEMUtil("CRL");

    private final BouncyCastleFipsProvider fipsProvider;

    private ASN1Set sData = null;
    private int                sDataObjectCount = 0;
    private InputStream currentStream = null;
    private ASN1StreamParser  currentAsn1Parser = null;
    private ASN1Set sCrlData = null;
    private int                sCrlDataObjectCount = 0;
    private InputStream currentCrlStream = null;
    private SignedDataParser signedDataParser = null;

    CertificateFactory(BouncyCastleFipsProvider fipsProvider)
    {
        this.fipsProvider = fipsProvider;
    }

    private java.security.cert.Certificate readDERCertificate()
        throws IOException, CertificateParsingException
    {
        ASN1SequenceParser seq = (ASN1SequenceParser)currentAsn1Parser.readObject();
        ASN1Encodable first = seq.readObject();

        if (first instanceof ASN1ObjectIdentifier)
        {
            if (first.equals(PKCSObjectIdentifiers.signedData))
            {
                signedDataParser = SignedDataParser.getInstance(((BERTaggedObjectParser)seq.readObject()).getObjectParser(1, true));

                signedDataParser.getDigestAlgorithms().toASN1Primitive();

                ASN1Encodable content = signedDataParser.getEncapContentInfo().getContent(0);
                if (content != null)
                {
                    content.toASN1Primitive();
                }

                ASN1SetParser setParser = signedDataParser.getCertificates();
                if (setParser != null)
                {
                    sData = pruneSet(setParser);

                    return getCertificate();
                }
                return null;
            }
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(first.toASN1Primitive());
        ASN1Encodable o;

        while ((o = seq.readObject()) != null)
        {
            v.add(o.toASN1Primitive());
        }

        return new X509CertificateObject(fipsProvider,
                            Certificate.getInstance(new DERSequence(v)));
    }

    private ASN1Set pruneSet(ASN1SetParser setParser)
    {
        ASN1Set certs = ASN1Set.getInstance(setParser.toASN1Primitive());
        ASN1EncodableVector v = new ASN1EncodableVector();
        // prune out attribute certificates.
        for (Enumeration en = certs.getObjects(); en.hasMoreElements();)
        {
            ASN1Encodable obj = (ASN1Encodable)en.nextElement();

            if (obj instanceof ASN1Sequence)
            {
                v.add(obj);
            }
        }

        return new DERSet(v);
    }

    private java.security.cert.Certificate getCertificate()
        throws CertificateParsingException, IOException
    {
        if (sData != null)
        {
            while (sDataObjectCount < sData.size())
            {
                Object obj = sData.getObjectAt(sDataObjectCount++);

                if (obj instanceof ASN1Sequence)
                {
                    if (sDataObjectCount == sData.size())
                    {
                        ASN1SetParser setParser = signedDataParser.getCrls();
                        if (setParser != null)
                        {
                            setParser.toASN1Primitive();
                        }
                        setParser = signedDataParser.getSignerInfos();
                        if (setParser != null)
                        {
                            setParser.toASN1Primitive();
                        }
                    }
                   return new X509CertificateObject(fipsProvider,
                                    Certificate.getInstance(obj));
                }
            }
        }

        return null;
    }

    private java.security.cert.Certificate readPEMCertificate(
        InputStream in)
        throws IOException, CertificateParsingException
    {
        ASN1Sequence seq = PEM_CERT_PARSER.readPEMObject(in);

        if (seq != null)
        {
            return new X509CertificateObject(fipsProvider,
                            Certificate.getInstance(seq));
        }

        return null;
    }

    protected CRL createCRL(CertificateList c)
    throws CRLException
    {
        return new X509CRLObject(fipsProvider, c);
    }
    
    private CRL readPEMCRL(
        InputStream in)
        throws IOException, CRLException
    {
        ASN1Sequence seq = PEM_CRL_PARSER.readPEMObject(in);

        if (seq != null)
        {
            return createCRL(
                            CertificateList.getInstance(seq));
        }

        return null;
    }

    private CRL readDERCRL()
        throws IOException, CRLException
    {
        ASN1SequenceParser seq = (ASN1SequenceParser)currentAsn1Parser.readObject();
        ASN1Encodable first = seq.readObject();

        if (first instanceof ASN1ObjectIdentifier)
        {
            if (first.equals(PKCSObjectIdentifiers.signedData))
            {
                signedDataParser = SignedDataParser.getInstance(((BERTaggedObjectParser)seq.readObject()).getObjectParser(1, true));

                signedDataParser.getDigestAlgorithms().toASN1Primitive();

                ASN1Encodable content = signedDataParser.getEncapContentInfo().getContent(0);
                if (content != null)
                {
                    content.toASN1Primitive();
                }
                signedDataParser.getCertificates().toASN1Primitive();

                ASN1SetParser setParser = signedDataParser.getCrls();
                if (setParser != null)
                {
                    sCrlData = pruneSet(setParser);

                    return getCRL();
                }
                return null;
            }
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(first.toASN1Primitive());
        ASN1Encodable o;

        while ((o = seq.readObject()) != null)
        {
            v.add(o.toASN1Primitive());
        }

        return createCRL(
                     CertificateList.getInstance(new DERSequence(v)));
    }

    private CRL getCRL()
        throws CRLException, IOException
    {
        if (sCrlData != null)
        {
            while (sCrlDataObjectCount < sCrlData.size())
            {
                Object obj = sCrlData.getObjectAt(sCrlDataObjectCount++);

                if (obj instanceof ASN1Sequence)
                {
                    if (sCrlDataObjectCount == sCrlData.size())
                    {
                        ASN1SetParser setParser = signedDataParser.getSignerInfos();
                        if (setParser != null)
                        {
                            setParser.toASN1Primitive();
                        }
                    }
                   return createCRL(CertificateList.getInstance(obj));
                }
            }
        }

        return null;
    }

    private java.security.cert.Certificate readCertificate(InputStream in)
        throws CertificateException
    {
        if (currentStream == null)
        {
            currentStream = in;
            sData = null;
            sDataObjectCount = 0;
        }
        else if (currentStream != in) // reset if input stream has changed
        {
            currentStream = in;
            sData = null;
            sDataObjectCount = 0;
        }

        java.security.cert.Certificate certificate = null;

        try
        {
            if (sData != null)
            {
                if (sDataObjectCount != sData.size())
                {
                    certificate = getCertificate();
                }
                else
                {
                    sData = null;
                    sDataObjectCount = 0;
                }
            }

            if (certificate == null)
            {
                InputStream pis;

                if (in.markSupported())
                {
                    pis = in;
                }
                else
                {
                    pis = new ByteArrayInputStream(Streams.readAll(in));
                }

                pis.mark(1);
                int tag = pis.read();

                if (tag == -1)
                {
                    return null;
                }

                pis.reset();

                if (tag != 0x30)  // assume ascii PEM encoded.
                {
                    certificate = readPEMCertificate(pis);
                }
                else
                {
                    currentAsn1Parser = new ASN1StreamParser(pis);

                    certificate = readDERCertificate();
                }
            }
        }
        catch (CertificateException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new CertificateException(e.getMessage(), e);
        }

        return certificate;
    }

    /**
     * Generates a certificate object and initializes it with the data
     * read from the input stream inStream.
     */
    public java.security.cert.Certificate engineGenerateCertificate(
        InputStream in)
        throws CertificateException
    {
        java.security.cert.Certificate certificate = readCertificate(in);
        if (certificate != null)
        {
            return certificate;
        }

        // not sure what we read, but there was no cert!
        throw new CertificateException("Unexpected data detected in stream");
    }

    /**
     * Returns a (possibly empty) collection view of the certificates
     * read from the given input stream inStream.
     */
    public Collection engineGenerateCertificates(
        InputStream inStream)
        throws CertificateException
    {
        List certs = new ArrayList();
        BufferedInputStream in = new BufferedInputStream(inStream);

        java.security.cert.Certificate certificate;
        while ((certificate = readCertificate(in)) != null)
        {
            certs.add(certificate);
        }

        return certs;
    }

    private CRL readCrl(InputStream inStream)
        throws CRLException
    {
        if (currentCrlStream == null)
        {
            currentCrlStream = inStream;
            sCrlData = null;
            sCrlDataObjectCount = 0;
        }
        else if (currentCrlStream != inStream) // reset if input stream has changed
        {
            currentCrlStream = inStream;
            sCrlData = null;
            sCrlDataObjectCount = 0;
        }

        CRL crl = null;

        try
        {
            if (sCrlData != null)
            {
                if (sCrlDataObjectCount != sCrlData.size())
                {
                    crl = getCRL();
                }
                else
                {
                    sCrlData = null;
                    sCrlDataObjectCount = 0;
                }
            }

            if (crl == null)
            {
                InputStream pis;

                if (inStream.markSupported())
                {
                    pis = inStream;
                }
                else
                {
                    pis = new ByteArrayInputStream(Streams.readAll(inStream));
                }

                pis.mark(1);
                int tag = pis.read();

                if (tag == -1)
                {
                    return null;
                }

                pis.reset();
                if (tag != 0x30)  // assume ascii PEM encoded.
                {
                    crl = readPEMCRL(pis);
                }
                else
                {       // lazy evaluate to help processing of large CRLs
                    currentAsn1Parser = new ASN1StreamParser(pis);

                    crl = readDERCRL();
                }
            }
        }
        catch (CRLException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new CRLException(e.toString(), e);
        }

        return crl;
    }

    /**
     * Generates a certificate revocation list (CRL) object and initializes
     * it with the data read from the input stream inStream.
     */
    public CRL engineGenerateCRL(
        InputStream inStream)
        throws CRLException
    {
        CRL crl = readCrl(inStream);

        if (crl != null)
        {
            return crl;
        }

        // not sure what we read, but there was no CRL!

        throw new CRLException("unexpected data detected in stream");
    }

    /**
     * Returns a (possibly empty) collection view of the CRLs read from
     * the given input stream inStream.
     *
     * The inStream may contain a sequence of DER-encoded CRLs, or
     * a PKCS#7 CRL set.  This is a PKCS#7 SignedData object, with the
     * only signficant field being crls.  In particular the signature
     * and the contents are ignored.
     */
    public Collection engineGenerateCRLs(
        InputStream inStream)
        throws CRLException
    {
        List crls = new ArrayList();
        BufferedInputStream in = new BufferedInputStream(inStream);

        CRL crl;
        while ((crl = readCrl(in)) != null)
        {
            crls.add(crl);
        }

        return crls;
    }

    public Iterator engineGetCertPathEncodings()
    {
        return PKIXCertPath.certPathEncodings.iterator();
    }

    public CertPath engineGenerateCertPath(
        InputStream inStream)
        throws CertificateException
    {
        return engineGenerateCertPath(inStream, "PkiPath");
    }

    public CertPath engineGenerateCertPath(
        InputStream inStream,
        String encoding)
        throws CertificateException
    {
        return new PKIXCertPath(fipsProvider, inStream, encoding);
    }

    public CertPath engineGenerateCertPath(
        List certificates)
        throws CertificateException
    {
        Iterator iter = certificates.iterator();
        Object obj;
        while (iter.hasNext())
        {
            obj = iter.next();
            if (obj != null)
            {
                if (!(obj instanceof X509Certificate))
                {
                    throw new CertificateException("List contains non X509Certificate object while creating CertPath\n" + obj.toString());
                }
            }
        }
        return new PKIXCertPath(fipsProvider, certificates);
    }
}
