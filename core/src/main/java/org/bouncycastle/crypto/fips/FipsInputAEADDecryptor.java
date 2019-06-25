package org.bouncycastle.crypto.fips;

import java.io.InputStream;

import org.bouncycastle.crypto.InputAEADDecryptor;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode InputAEADDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsInputAEADDecryptor<T extends Parameters>
    implements InputAEADDecryptor<T>
{
    // package protect construction
    FipsInputAEADDecryptor()
    {
    }

    public abstract T getParameters();

    public abstract UpdateOutputStream getAADStream();

    public abstract InputStream getDecryptingStream(InputStream in);

    public abstract byte[] getMAC();
}
