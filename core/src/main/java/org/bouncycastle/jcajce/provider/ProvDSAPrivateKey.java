package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPrivateKey;
import org.bouncycastle.util.Strings;

class ProvDSAPrivateKey
    implements DSAPrivateKey, ProvKey<AsymmetricDSAPrivateKey>
{
    private static final long serialVersionUID = -4677259546958385734L;

    private transient AsymmetricDSAPrivateKey baseKey;

    ProvDSAPrivateKey(
        Algorithm algorithm,
        DSAPrivateKey key)
     {
         this.baseKey = new AsymmetricDSAPrivateKey(algorithm, DSAUtils.extractParams(key.getParams()), key.getX());
     }

    ProvDSAPrivateKey(
        Algorithm algorithm,
        DSAPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDSAPrivateKey(algorithm, DSAUtils.extractParams(keySpec), keySpec.getX());
    }

    ProvDSAPrivateKey(
        AsymmetricDSAPrivateKey key)
    {
        this.baseKey = key;
    }

    public BigInteger getX()
    {
        return baseKey.getX();
    }

    public DSAParams getParams()
    {
        return DSAUtils.convertParams(baseKey.getDomainParameters());
    }

    public AsymmetricDSAPrivateKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return "DSA";
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
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("DSA Private Key").append(nl);
        try
        {
            buf.append("    X: ").append(this.getX().toString(16)).append(nl);
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

        if (!(o instanceof ProvDSAPrivateKey))
        {
            return false;
        }

        ProvDSAPrivateKey other = (ProvDSAPrivateKey)o;

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

        baseKey = new AsymmetricDSAPrivateKey(alg, enc);
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
