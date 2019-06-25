package org.bouncycastle.crypto.fips;

import java.io.OutputStream;

import org.bouncycastle.crypto.OutputDecryptor;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the approved mode OutputDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsOutputDecryptor<T extends Parameters>
    implements OutputDecryptor<T>
{
     // package protect construction
    FipsOutputDecryptor()
    {
    }

    public abstract T getParameters();

    public abstract org.bouncycastle.crypto.CipherOutputStream getDecryptingStream(OutputStream out);
}
