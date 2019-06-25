package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;
import org.bouncycastle.util.Strings;

class ProvDHPrivateKey
    implements DHPrivateKey
{
    static final long serialVersionUID = 311058815616901812L;

    private transient AsymmetricDHPrivateKey baseKey;

    ProvDHPrivateKey(
        Algorithm algorithm,
        DHPrivateKey key)
     {
         this.baseKey = new AsymmetricDHPrivateKey(algorithm, DHUtils.extractParams(key.getParams()), key.getX());
     }

    ProvDHPrivateKey(
        Algorithm algorithm,
        DHPrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDHPrivateKey(algorithm, DHUtils.extractParams(keySpec), keySpec.getX());
    }

    ProvDHPrivateKey(
        AsymmetricDHPrivateKey key)
    {
        this.baseKey = key;
    }


    public String getAlgorithm()
    {
        return "DH";
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

    public DHParameterSpec getParams()
    {
        return DHUtils.convertParams(baseKey.getDomainParameters());
    }

    public BigInteger getX()
    {
        return baseKey.getX();
    }

    AsymmetricDHPrivateKey getBaseKey()
    {
        return baseKey;
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("DH Private Key").append(nl);
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

        if (!(o instanceof ProvDHPrivateKey))
        {
            return false;
        }

        ProvDHPrivateKey other = (ProvDHPrivateKey)o;

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

        baseKey = new AsymmetricDHPrivateKey(alg, enc);
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
