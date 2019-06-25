package org.bouncycastle.crypto.fips;

import java.io.OutputStream;

import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.OutputEncryptor;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the approved mode OutputEncryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this encryptor.
 */
public abstract class FipsOutputEncryptor<T extends Parameters>
    implements OutputEncryptor<T>
{
     // package protect construction
    FipsOutputEncryptor()
    {
    }

    public abstract T getParameters();

    public abstract CipherOutputStream getEncryptingStream(OutputStream out);
}
