package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Class for keys for GOST R 34.10-2001 (ECGOST) public keys.
 */
public final class AsymmetricECGOST3410PublicKey
    extends AsymmetricGOST3410Key<ECDomainParameters>
    implements AsymmetricPublicKey
{
    private ECPoint w;

    public AsymmetricECGOST3410PublicKey(Algorithm algorithm, GOST3410Parameters<ECDomainParameters> params, ECPoint w)
    {
        super(algorithm, params);

        this.w = KeyUtils.validated(w);
    }

    public AsymmetricECGOST3410PublicKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(enc));
    }

    public AsymmetricECGOST3410PublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(algorithm, CryptoProObjectIdentifiers.gostR3410_2001, publicKeyInfo.getAlgorithm());

        this.w = KeyUtils.validated(parsePublicKey(publicKeyInfo));
    }

    private ECPoint parsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        ASN1OctetString key;

        try
        {
            key = ASN1OctetString.getInstance(publicKeyInfo.parsePublicKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error recovering public key: " + e.getMessage(), e);
        }

        byte[] keyEnc = key.getOctets();
        byte[] x = new byte[32];
        byte[] y = new byte[32];

        for (int i = 0; i != x.length; i++)
        {
            x[i] = keyEnc[32 - 1 - i];
        }

        for (int i = 0; i != y.length; i++)
        {
            y[i] = keyEnc[64 - 1 - i];
        }

        return this.getParameters().getDomainParameters().getCurve().validatePoint(new BigInteger(1, x), new BigInteger(1, y));
    }

    public ECPoint getW()
    {
        return w;
    }

    public byte[] getEncoded()
    {
        BigInteger bX = this.w.getAffineXCoord().toBigInteger();
        BigInteger bY = this.w.getAffineYCoord().toBigInteger();
        byte[] encKey = new byte[64];

        extractBytes(encKey, 0, bX);
        extractBytes(encKey, 32, bY);

        if (getParameters().getPublicKeyParamSet() != null)
        {
            GOST3410PublicKeyAlgParameters pubParams = new GOST3410PublicKeyAlgParameters(getParameters().getPublicKeyParamSet(), getParameters().getDigestParamSet(), getParameters().getEncryptionParamSet());

            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, pubParams), new DEROctetString(encKey));
        }
        else
        {
            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001), new DEROctetString(encKey));
        }
    }

    private void extractBytes(byte[] encKey, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < 32)
        {
            byte[] tmp = new byte[32];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != 32; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricECGOST3410PublicKey))
        {
            return false;
        }

        AsymmetricECGOST3410PublicKey other = (AsymmetricECGOST3410PublicKey)o;

        return w.equals(other.w) && this.getParameters().equals(other.getParameters());
    }

    @Override
    public int hashCode()
    {
        int result = w.hashCode();
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }
}
