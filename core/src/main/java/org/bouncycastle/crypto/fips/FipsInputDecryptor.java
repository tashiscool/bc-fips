package org.bouncycastle.crypto.fips;

import java.io.InputStream;

import org.bouncycastle.crypto.InputDecryptor;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the approved mode InputDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsInputDecryptor<T extends Parameters>
    implements InputDecryptor<T>
{
    // package protect construction
    FipsInputDecryptor()
    {
    }

    public abstract T getParameters();

    public abstract InputStream getDecryptingStream(InputStream in);
}
