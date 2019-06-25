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

/**
 * Class for keys for GOST R 34.10-1994 public keys.
 */
public final class AsymmetricGOST3410PublicKey
    extends AsymmetricGOST3410Key<GOST3410DomainParameters>
    implements AsymmetricPublicKey
{
    private BigInteger y;

    public AsymmetricGOST3410PublicKey(Algorithm algorithm, GOST3410Parameters<GOST3410DomainParameters> params, BigInteger y)
    {
        super(algorithm, params);

        this.y = y;
    }

    public AsymmetricGOST3410PublicKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(enc));
    }

    public AsymmetricGOST3410PublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(algorithm, CryptoProObjectIdentifiers.gostR3410_94, publicKeyInfo.getAlgorithm());

        this.y = parsePublicKey(publicKeyInfo);
    }

    private static BigInteger parsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        try
        {
            ASN1OctetString derY = ASN1OctetString.getInstance(publicKeyInfo.parsePublicKey());

            byte[]                  keyEnc = derY.getOctets();
            byte[]                  keyBytes = new byte[keyEnc.length];

            for (int i = 0; i != keyEnc.length; i++)
            {
                keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // was little endian
            }

            return new BigInteger(1, keyBytes);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in GOST3410 public key");
        }
    }

    public BigInteger getY()
    {
        return y;
    }

    public byte[] getEncoded()
    {
        byte[]                  keyEnc = this.getY().toByteArray();
        byte[]                  keyBytes;

        if (keyEnc[0] == 0)
        {
            keyBytes = new byte[keyEnc.length - 1];
        }
        else
        {
            keyBytes = new byte[keyEnc.length];
        }

        for (int i = 0; i != keyBytes.length; i++)
        {
            keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // must be little endian
        }

        if (getParameters().getPublicKeyParamSet() != null)
        {
            GOST3410PublicKeyAlgParameters pubParams = new GOST3410PublicKeyAlgParameters(getParameters().getPublicKeyParamSet(), getParameters().getDigestParamSet(), getParameters().getEncryptionParamSet());

            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, pubParams), new DEROctetString(keyBytes));
        }
        else
        {
            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94), new DEROctetString(keyBytes));
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricGOST3410PublicKey))
        {
            return false;
        }

        AsymmetricGOST3410PublicKey other = (AsymmetricGOST3410PublicKey)o;

        return y.equals(other.getY()) && this.getParameters().equals(other.getParameters());
    }

    @Override
    public int hashCode()
    {
        int result = y.hashCode();
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }
}
