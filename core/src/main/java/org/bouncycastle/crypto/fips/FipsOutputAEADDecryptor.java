package org.bouncycastle.crypto.fips;

import java.io.OutputStream;

import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.OutputAEADDecryptor;
import org.bouncycastle.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode OutputAEADDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsOutputAEADDecryptor<T extends FipsParameters>
    extends FipsOutputDecryptor<T>
    implements OutputAEADDecryptor<T>
{
    // package protect construction
    FipsOutputAEADDecryptor()
    {
    }

    public abstract UpdateOutputStream getAADStream();

    public abstract CipherOutputStream getDecryptingStream(OutputStream out);

    public abstract byte[] getMAC();
}
