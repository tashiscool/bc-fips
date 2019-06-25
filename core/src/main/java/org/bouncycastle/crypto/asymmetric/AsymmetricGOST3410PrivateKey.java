package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Class for keys for GOST R 34.10-1994 private keys.
 */
public final class AsymmetricGOST3410PrivateKey
    extends AsymmetricGOST3410Key<GOST3410DomainParameters>
    implements AsymmetricPrivateKey
{
    private final int hashCode;

    private BigInteger x;

    public AsymmetricGOST3410PrivateKey(Algorithm algorithm, GOST3410Parameters<GOST3410DomainParameters> params, BigInteger x)
    {
        super(algorithm, params);

        this.x = x;
        this.hashCode = calculateHashCode();
    }

    public AsymmetricGOST3410PrivateKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, PrivateKeyInfo.getInstance(enc));
    }

    public AsymmetricGOST3410PrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
    {
        super(algorithm, CryptoProObjectIdentifiers.gostR3410_94, privateKeyInfo.getPrivateKeyAlgorithm());

        this.x = parsePrivateKey(privateKeyInfo);
        this.hashCode = calculateHashCode();
    }

    private static BigInteger parsePrivateKey(PrivateKeyInfo info)
    {
        try
        {
            ASN1OctetString derX = ASN1OctetString.getInstance(info.parsePrivateKey());
            byte[]              keyEnc = derX.getOctets();
            byte[]              keyBytes = new byte[keyEnc.length];

            for (int i = 0; i != keyEnc.length; i++)
            {
                keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // was little endian
            }

            return new BigInteger(1, keyBytes);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to parse DSA private key: " + e.getMessage(), e);
        }
    }

    public final byte[] getEncoded()
    {
        byte[]                  keyEnc = this.getX().toByteArray();
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

        GOST3410Parameters<GOST3410DomainParameters> params = this.getParameters();

        if (params.getEncryptionParamSet() != null)
        {
            return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(params.getPublicKeyParamSet(), params.getDigestParamSet(), params.getEncryptionParamSet())), new DEROctetString(keyBytes));
        }
        return KeyUtils.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(params.getPublicKeyParamSet(), params.getDigestParamSet())), new DEROctetString(keyBytes));
    }

    public BigInteger getX()
    {
        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        return x;
    }

    private void zeroize()
    {
        this.x = null;
    }

    @Override
    public int hashCode()
    {
        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = x.hashCode();
        result = 31 * result + this.getParameters().hashCode();
        return result;
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        zeroize();
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricGOST3410PrivateKey))
        {
            return false;
        }

        AsymmetricGOST3410PrivateKey other = (AsymmetricGOST3410PrivateKey)o;

        return x.equals(other.x) && this.getParameters().equals(other.getParameters());
    }
}
