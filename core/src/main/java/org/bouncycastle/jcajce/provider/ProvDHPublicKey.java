package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPublicKey;
import org.bouncycastle.util.Strings;

class ProvDHPublicKey
    implements DHPublicKey
{
    static final long serialVersionUID = -216691575254424324L;

    private transient AsymmetricDHPublicKey baseKey;

    ProvDHPublicKey(
        Algorithm algorithm,
        DHPublicKey baseKey)
    {
        this.baseKey = new AsymmetricDHPublicKey(algorithm, DHUtils.extractParams(baseKey.getParams()), baseKey.getY());
    }

    ProvDHPublicKey(
        Algorithm algorithm,
        DHPublicKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDHPublicKey(algorithm, DHUtils.extractParams(keySpec), keySpec.getY());
    }

    ProvDHPublicKey(
        AsymmetricDHPublicKey baseKey)
    {
        this.baseKey = baseKey;
    }

    public String getAlgorithm()
    {
        return "DH";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public DHParameterSpec getParams()
    {
        return DHUtils.convertParams(baseKey.getDomainParameters());
    }

    public BigInteger getY()
    {
        return baseKey.getY();
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    AsymmetricDHPublicKey getBaseKey()
    {
        return baseKey;
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("DH Public Key").append(nl);
        buf.append("    Y: ").append(this.getY().toString(16)).append(nl);

        return buf.toString();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvDHPublicKey))
        {
            return false;
        }

        ProvDHPublicKey other = (ProvDHPublicKey)o;

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

        baseKey = new AsymmetricDHPublicKey(alg, enc);
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
