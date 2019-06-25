package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.util.Strings;

class ProvRSAPrivateKey
    implements RSAPrivateKey, ProvKey<AsymmetricRSAPrivateKey>
{
    static final long serialVersionUID = 5110188922551353628L;

    private transient AsymmetricRSAPrivateKey baseKey;

    ProvRSAPrivateKey(
        Algorithm algorithm,
        RSAPrivateKey key)
     {
         this.baseKey = new AsymmetricRSAPrivateKey(algorithm, key.getModulus(), key.getPrivateExponent());
     }

    ProvRSAPrivateKey(
        Algorithm algorithm,
        RSAPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricRSAPrivateKey(algorithm, keySpec.getModulus(), keySpec.getPrivateExponent());
    }

    ProvRSAPrivateKey(
        AsymmetricRSAPrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricRSAPrivateKey getBaseKey()
    {
        return baseKey;
    }

    public BigInteger getModulus()
    {
        return baseKey.getModulus();
    }

    public BigInteger getPrivateExponent()
    {
        return baseKey.getPrivateExponent();
    }

    public String getAlgorithm()
    {
        return "RSA";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        buf.append("RSA Private Key").append(nl);
        buf.append("             modulus: ").append(this.getModulus().toString(16)).append(nl);
        try
        {
            buf.append("    private exponent: ").append(this.getPrivateExponent().toString(16)).append(nl);
        }
        catch (Exception e)
        {
            buf.append("RESTRICTED").append(nl);
        }

        return buf.toString();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvRSAPrivateKey))
        {
            return false;
        }

        ProvRSAPrivateKey other = (ProvRSAPrivateKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricRSAPrivateKey(alg, enc);
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
