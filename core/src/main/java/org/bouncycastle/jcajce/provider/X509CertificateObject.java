package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

class X509CertificateObject
    extends X509Certificate
{
    private final BouncyCastleFipsProvider fipsProvider;
    private final org.bouncycastle.asn1.x509.Certificate    c;
    private final BasicConstraints            basicConstraints;
    private final boolean[]                   keyUsage;

    private volatile PublicKey          publicKeyValue;
    private volatile boolean            hashValueSet;
    private volatile int                hashValue;

    public X509CertificateObject(
        BouncyCastleFipsProvider fipsProvider,
        org.bouncycastle.asn1.x509.Certificate c)
        throws CertificateParsingException
    {
        this.fipsProvider = fipsProvider;
        this.c = c;

        try
        {
            byte[]  bytes = this.getExtensionBytes("2.5.29.19");

            if (bytes != null)
            {
                basicConstraints = BasicConstraints.getInstance(ASN1Primitive.fromByteArray(bytes));
            }
            else
            {
                basicConstraints = null;
            }
        }
        catch (Exception e)
        {
            throw new CertificateParsingException("cannot construct BasicConstraints: " + e);
        }

        try
        {
            byte[] bytes = this.getExtensionBytes("2.5.29.15");
            if (bytes != null)
            {
                DERBitString    bits = DERBitString.getInstance(ASN1Primitive.fromByteArray(bytes));

                bytes = bits.getBytes();
                int length = (bytes.length * 8) - bits.getPadBits();

                keyUsage = new boolean[(length < 9) ? 9 : length];

                for (int i = 0; i != length; i++)
                {
                    keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                }
            }
            else
            {
                keyUsage = null;
            }
        }
        catch (Exception e)
        {
            throw new CertificateParsingException("cannot construct KeyUsage: " + e);
        }
    }

    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        this.checkValidity(new Date());
    }

    public void checkValidity(
        Date date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        if (date.getTime() > this.getNotAfter().getTime())  // for other VM compatibility
        {
            throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
        }

        if (date.getTime() < this.getNotBefore().getTime())
        {
            throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
        }
    }

    public int getVersion()
    {
        return c.getVersionNumber();
    }

    public BigInteger getSerialNumber()
    {
        return c.getSerialNumber().getValue();
    }

    public Principal getIssuerDN()
    {
        return getIssuerX500Principal();
    }

    public X500Principal getIssuerX500Principal()
    {
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(c.getIssuer());

            return new X500Principal(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN: " + e.getMessage(), e);
        }
    }

    public Principal getSubjectDN()
    {
        return getSubjectX500Principal();
    }

    public X500Principal getSubjectX500Principal()
    {
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(c.getSubject());

            return new X500Principal(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN: " + e.getMessage(), e);
        }
    }

    public Date getNotBefore()
    {
        return c.getStartDate().getDate();
    }

    public Date getNotAfter()
    {
        return c.getEndDate().getDate();
    }

    public byte[] getTBSCertificate()
        throws CertificateEncodingException
    {
        try
        {
            return c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public byte[] getSignature()
    {
        return c.getSignature().getOctets();
    }

    /**
     * return a more "meaningful" representation for the signature algorithm used in
     * the certificate.
     */
    public String getSigAlgName()
    {
        Provider prov = fipsProvider;

        if (prov != null)
        {
            String algName = prov.getProperty("Alg.Alias.Signature." + this.getSigAlgOID());

            if (algName != null)
            {
                return algName;
            }
        }

        Provider[] provs = Security.getProviders();

        //
        // search every provider looking for a real algorithm
        //
        for (int i = 0; i != provs.length; i++)
        {
            String algName = provs[i].getProperty("Alg.Alias.Signature." + this.getSigAlgOID());
            if (algName != null)
            {
                return algName;
            }
        }

        return this.getSigAlgOID();
    }

    /**
     * return the object identifier for the signature.
     */
    public String getSigAlgOID()
    {
        return c.getSignatureAlgorithm().getAlgorithm().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getSigAlgParams()
    {
        if (c.getSignatureAlgorithm().getParameters() != null)
        {
            try
            {
                return c.getSignatureAlgorithm().getParameters().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                return null;
            }
        }
        else
        {
            return null;
        }
    }

    public boolean[] getIssuerUniqueID()
    {
        DERBitString    id = c.getTBSCertificate().getIssuerUniqueId();

        if (id != null)
        {
            byte[]          bytes = id.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }
            
        return null;
    }

    public boolean[] getSubjectUniqueID()
    {
        DERBitString    id = c.getTBSCertificate().getSubjectUniqueId();

        if (id != null)
        {
            byte[]          bytes = id.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }
            
        return null;
    }

    public boolean[] getKeyUsage()
    {
        return keyUsage;
    }

    public List getExtendedKeyUsage()
        throws CertificateParsingException
    {
        byte[]  bytes = this.getExtensionBytes("2.5.29.37");

        if (bytes != null)
        {
            try
            {
                ASN1Sequence    seq = ASN1Sequence.getInstance(bytes);
                List list = new ArrayList();

                for (int i = 0; i != seq.size(); i++)
                {
                    list.add(((ASN1ObjectIdentifier)seq.getObjectAt(i)).getId());
                }
                
                return Collections.unmodifiableList(list);
            }
            catch (Exception e)
            {
                throw new CertificateParsingException("error processing extended key usage extension");
            }
        }

        return null;
    }
    
    public int getBasicConstraints()
    {
        if (basicConstraints != null)
        {
            if (basicConstraints.isCA())
            {
                if (basicConstraints.getPathLenConstraint() == null)
                {
                    return Integer.MAX_VALUE;
                }
                else
                {
                    return basicConstraints.getPathLenConstraint().intValue();
                }
            }
            else
            {
                return -1;
            }
        }

        return -1;
    }

    public Collection getSubjectAlternativeNames()
        throws CertificateParsingException
    {
        return getAlternativeNames(getExtensionBytes(Extension.subjectAlternativeName.getId()));
    }

    public Collection getIssuerAlternativeNames()
        throws CertificateParsingException
    {
        return getAlternativeNames(getExtensionBytes(Extension.issuerAlternativeName.getId()));
    }

    public Set getCriticalExtensionOIDs()
    {
        if (this.getVersion() == 3)
        {
            Set set = new HashSet();
            Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration e = extensions.oids();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    private byte[] getExtensionBytes(String oid)
    {
        Extensions exts = c.getTBSCertificate().getExtensions();

        if (exts != null)
        {
            Extension   ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
            if (ext != null)
            {
                return ext.getExtnValue().getOctets();
            }
        }

        return null;
    }

    public byte[] getExtensionValue(String oid)
    {
        Extensions exts = c.getTBSCertificate().getExtensions();

        if (exts != null)
        {
            Extension   ext = exts.getExtension(new ASN1ObjectIdentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getExtnValue().getEncoded();
                }
                catch (Exception e)
                {
                    throw new IllegalStateException("error parsing " + e.toString());
                }
            }
        }

        return null;
    }

    public Set getNonCriticalExtensionOIDs()
    {
        if (this.getVersion() == 3)
        {
            Set set = new HashSet();
            Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration e = extensions.oids();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    Extension       ext = extensions.getExtension(oid);

                    if (!ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public boolean hasUnsupportedCriticalExtension()
    {
        if (this.getVersion() == 3)
        {
            Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Set critical = getCriticalExtensionOIDs();

                critical.removeAll(RFC3280CertPathUtilities.CERT_SUPPORTED_CRITICAL_EXTENSIONS);

                return !critical.isEmpty();
            }
        }

        return false;
    }

    public PublicKey getPublicKey()
    {
        try
        {
            // we cache the public key as assurance checking can be quite expensive
            if (publicKeyValue == null)
            {
                publicKeyValue = fipsProvider.getPublicKey(c.getSubjectPublicKeyInfo());
            }
            return publicKeyValue;
        }
        catch (IOException e)
        {
            return null;   // should never happen...
        }
    }

    public byte[] getEncoded()
        throws CertificateEncodingException
    {
        try
        {
            return c.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof X509CertificateObject)
        {
            X509CertificateObject other = (X509CertificateObject)o;

            if (this.hashValueSet && other.hashValueSet)
            {
                if (this.hashValue != other.hashValue)
                {
                    return false;
                }
            }

            return this.c.equals(other.c);
        }

        return super.equals(o);
    }
    
    public int hashCode()
    {
        if (!hashValueSet)
        {
            hashValue = super.hashCode();
            hashValueSet = true;
        }

        return hashValue;
    }

    public String toString()
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        buf.append("  [0]         Version: ").append(this.getVersion()).append(nl);
        buf.append("         SerialNumber: ").append(this.getSerialNumber()).append(nl);
        buf.append("             IssuerDN: ").append(this.getIssuerDN()).append(nl);
        buf.append("           Start Date: ").append(this.getNotBefore()).append(nl);
        buf.append("           Final Date: ").append(this.getNotAfter()).append(nl);
        buf.append("            SubjectDN: ").append(this.getSubjectDN()).append(nl);
        buf.append("           Public Key: ").append(this.getPublicKey()).append(nl);
        buf.append("  Signature Algorithm: ").append(this.getSigAlgName()).append(nl);

        byte[]  sig = this.getSignature();

        buf.append("            Signature: ").append(Strings.fromByteArray(Hex.encode(sig, 0, 20))).append(nl);
        for (int i = 20; i < sig.length; i += 20)
        {
            if (i < sig.length - 20)
            {
                buf.append("                       ").append(Strings.fromByteArray(Hex.encode(sig, i, 20))).append(nl);
            }
            else
            {
                buf.append("                       ").append(Strings.fromByteArray(Hex.encode(sig, i, sig.length - i))).append(nl);
            }
        }

        Extensions extensions = c.getTBSCertificate().getExtensions();

        if (extensions != null)
        {
            Enumeration e = extensions.oids();

            if (e.hasMoreElements())
            {
                buf.append("       Extensions: \n");
            }

            while (e.hasMoreElements())
            {
                ASN1ObjectIdentifier     oid = (ASN1ObjectIdentifier)e.nextElement();
                Extension ext = extensions.getExtension(oid);

                if (ext.getExtnValue() != null)
                {
                    byte[]                  octs = ext.getExtnValue().getOctets();

                    buf.append("                       critical(").append(ext.isCritical()).append(") ");
                    try
                    {
                        ASN1Primitive         obj = ASN1Primitive.fromByteArray(octs);
                        if (oid.equals(Extension.basicConstraints))
                        {
                            buf.append(BasicConstraints.getInstance(obj)).append(nl);
                        }
                        else if (oid.equals(Extension.keyUsage))
                        {
                            buf.append(KeyUsage.getInstance(obj)).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeCertType))
                        {
                            buf.append(new NetscapeCertType((DERBitString)obj)).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeRevocationURL))
                        {
                            buf.append(new NetscapeRevocationURL((DERIA5String)obj)).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.verisignCzagExtension))
                        {
                            buf.append(new VerisignCzagExtension((DERIA5String)obj)).append(nl);
                        }
                        else 
                        {
                            buf.append(oid.getId());
                            buf.append(" value = ").append(ASN1Dump.dumpAsString(obj)).append(nl);
                            //buf.append(" value = ").append("*****").append(nl);
                        }
                    }
                    catch (Exception ex)
                    {
                        buf.append(oid.getId());
                   //     buf.append(" value = ").append(Strings.fromByteArray(Hex.encode(ext.getExtnValue().getOctets()))).append(nl);
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }

        return buf.toString();
    }

    public final void verify(
        PublicKey key)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
        Signature signature = getSignatureFromProvider(fipsProvider, sigName);
        
        checkSignature(key, signature);
    }
    
    public final void verify(
        PublicKey key,
        String sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
        Signature signature;

        if (sigProvider != null)
        {
            signature = Signature.getInstance(sigName, sigProvider);
        }
        else
        {
            signature = Signature.getInstance(sigName);
        }
        
        checkSignature(key, signature);
    }

    public final void verify(
        PublicKey key,
        Provider sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException
    {
        String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
        Signature signature;

        signature = getSignatureFromProvider(sigProvider, sigName);

        checkSignature(key, signature);
    }

    private Signature getSignatureFromProvider(Provider sigProvider, String sigName)
        throws NoSuchAlgorithmException
    {
        if (sigProvider != null)
        {
            try
            {
                return Signature.getInstance(sigName, sigProvider);
            }
            catch (Exception e)
            {
                return Signature.getInstance(sigName);
            }
        }
        else
        {
            return Signature.getInstance(sigName);
        }
    }

    private void checkSignature(
        PublicKey key,
        Signature signature)
        throws CertificateException, NoSuchAlgorithmException,
        SignatureException, InvalidKeyException
    {
        if (!isAlgIdEqual(c.getSignatureAlgorithm(), c.getTBSCertificate().getSignature()))
        {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }

        ASN1Encodable params = c.getSignatureAlgorithm().getParameters();

        // this needs to be called before initVerify
        X509SignatureUtil.setSignatureParameters(signature, params);

        signature.initVerify(key);

        signature.update(this.getTBSCertificate());

        if (!signature.verify(this.getSignature()))
        {
            throw new SignatureException("certificate does not verify with supplied key");
        }
    }

    private boolean isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
    {
        if (!id1.getAlgorithm().equals(id2.getAlgorithm()))
        {
            return false;
        }

        if (id1.getParameters() == null)
        {
            if (id2.getParameters() != null && !id2.getParameters().equals(DERNull.INSTANCE))
            {
                return false;
            }

            return true;
        }

        if (id2.getParameters() == null)
        {
            if (id1.getParameters() != null && !id1.getParameters().equals(DERNull.INSTANCE))
            {
                return false;
            }

            return true;
        }
        
        return id1.getParameters().equals(id2.getParameters());
    }

    private static Collection getAlternativeNames(byte[] extVal)
        throws CertificateParsingException
    {
        if (extVal == null)
        {
            return null;
        }
        try
        {
            Collection temp = new ArrayList();
            Enumeration it = ASN1Sequence.getInstance(extVal).getObjects();
            while (it.hasMoreElements())
            {
                GeneralName genName = GeneralName.getInstance(it.nextElement());
                List list = new ArrayList();
                list.add(Integers.valueOf(genName.getTagNo()));
                switch (genName.getTagNo())
                {
                case GeneralName.ediPartyName:
                case GeneralName.x400Address:
                case GeneralName.otherName:
                    list.add(genName.getEncoded());
                    break;
                case GeneralName.directoryName:
                    list.add(X500Name.getInstance(RFC4519Style.INSTANCE, genName.getName()).toString());
                    break;
                case GeneralName.dNSName:
                case GeneralName.rfc822Name:
                case GeneralName.uniformResourceIdentifier:
                    list.add(((ASN1String)genName.getName()).getString());
                    break;
                case GeneralName.registeredID:
                    list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
                    break;
                case GeneralName.iPAddress:
                    byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
                    final String addr;
                    try
                    {
                        addr = InetAddress.getByAddress(addrBytes).getHostAddress();
                    }
                    catch (UnknownHostException e)
                    {
                        continue;
                    }
                    list.add(addr);
                    break;
                default:
                    throw new IOException("Bad tag number: " + genName.getTagNo());
                }

                temp.add(Collections.unmodifiableList(list));
            }
            if (temp.size() == 0)
            {
                return null;
            }
            return Collections.unmodifiableCollection(temp);
        }
        catch (Exception e)
        {
            throw new CertificateParsingException(e.getMessage());
        }
    }
}
