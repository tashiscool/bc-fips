package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.util.Strings;

class ProvRSAPublicKey
    implements RSAPublicKey, ProvKey<AsymmetricRSAPublicKey>
{
    static final long serialVersionUID = 2675817738516720772L;

    private transient AsymmetricRSAPublicKey baseKey;

    ProvRSAPublicKey(
        Algorithm algorithm,
        RSAPublicKey baseKey)
    {
        this.baseKey = new AsymmetricRSAPublicKey(algorithm, baseKey.getModulus(), baseKey.getPublicExponent());
    }

    ProvRSAPublicKey(
        Algorithm algorithm,
        RSAPublicKeySpec baseKey)
    {
        this.baseKey = new AsymmetricRSAPublicKey(algorithm, baseKey.getModulus(), baseKey.getPublicExponent());
    }

    ProvRSAPublicKey(
        AsymmetricRSAPublicKey baseKey)
    {
        this.baseKey = baseKey;
    }

    public AsymmetricRSAPublicKey getBaseKey()
    {
        return baseKey;
    }

    /**
     * return the modulus.
     *
     * @return the modulus.
     */
    public BigInteger getModulus()
    {
        return baseKey.getModulus();
    }

    /**
     * return the public exponent.
     *
     * @return the public exponent.
     */
    public BigInteger getPublicExponent()
    {
        return baseKey.getPublicExponent();
    }

    public String getAlgorithm()
    {
        return "RSA";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvRSAPublicKey))
        {
            return false;
        }

        ProvRSAPublicKey other = (ProvRSAPublicKey)o;

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

        baseKey = new AsymmetricRSAPublicKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        buf.append("RSA Public Key").append(nl);
        buf.append("            modulus: ").append(this.getModulus().toString(16)).append(nl);
        buf.append("    public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);

        return buf.toString();
    }
}
