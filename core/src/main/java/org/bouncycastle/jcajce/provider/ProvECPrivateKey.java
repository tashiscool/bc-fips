package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.util.Strings;

class ProvECPrivateKey
    implements ECPrivateKey, ProvKey<AsymmetricECPrivateKey>
{
    static final long serialVersionUID = 994553197664784084L;

    private transient AsymmetricECPrivateKey baseKey;

    ProvECPrivateKey(
        Algorithm algorithm,
        ECPrivateKey key)
     {
         ECDomainParameters domainParameters = ECUtil.convertFromSpec(key.getParams());

         this.baseKey = new AsymmetricECPrivateKey(algorithm, domainParameters, key.getS());
     }

    ProvECPrivateKey(
        Algorithm algorithm,
        ECPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricECPrivateKey(algorithm, ECUtil.convertFromSpec(keySpec.getParams()), keySpec.getS());
    }

    ProvECPrivateKey(
        AsymmetricECPrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricECPrivateKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return "EC";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public ECParameterSpec getParams()
    {
        return ECUtil.convertToSpec(baseKey.getDomainParameters());
    }

    public BigInteger getS()
    {
        return baseKey.getS();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvECPrivateKey))
        {
            return false;
        }

        ProvECPrivateKey other = (ProvECPrivateKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("EC Private Key").append(nl);
        try
        {
            buf.append("    S: ").append(this.getS().toString(16)).append(nl);
        }
        catch (Exception e)
        {
            buf.append("RESTRICTED").append(nl);
        }

        return buf.toString();

    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricECPrivateKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }
}
