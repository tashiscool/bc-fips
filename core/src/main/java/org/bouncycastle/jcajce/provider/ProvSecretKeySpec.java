package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;

final class ProvSecretKeySpec
    extends SecretKeySpec
    implements ProvKey<SymmetricKey>
{
    private static final long serialVersionUID = -1861292622640337039L;

    private transient ValidatedSymmetricKey baseKey;

    public ProvSecretKeySpec(ValidatedSymmetricKey key)
    {
        this(key, Utils.getBaseName(key.getAlgorithm()));
    }

    public ProvSecretKeySpec(ValidatedSymmetricKey key, String standardName)
    {
        super(key.getKeyBytes(), standardName);

        this.baseKey = key;
    }

    public SymmetricKey getBaseKey()
    {
        return new SymmetricSecretKey(baseKey.getAlgorithm(), baseKey.getKeyBytes());
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new ValidatedSymmetricKey(alg, enc);
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
