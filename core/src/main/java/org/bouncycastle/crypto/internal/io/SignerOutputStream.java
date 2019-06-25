package org.bouncycastle.crypto.internal.io;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.internal.CryptoException;
import org.bouncycastle.crypto.internal.Signer;

public class SignerOutputStream
    extends UpdateOutputStream
{
    private final String algorithmName;
    private final boolean isApprovedMode;

    private Signer sig;

    public SignerOutputStream(String algorithmName, Signer sig)
    {
        this.algorithmName = algorithmName;
        this.isApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.sig = sig;
    }

    public void write(byte[] bytes, int off, int len)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        sig.update(bytes, off, len);
    }

    public void write(byte[] bytes)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        sig.update(bytes, 0, bytes.length);
    }

    public void write(int b)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        sig.update((byte)b);
    }

    byte[] getSignature()
        throws CryptoException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        return sig.generateSignature();
    }

    boolean verify(byte[] expected)
        throws InvalidSignatureException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        return sig.verifySignature(expected);
    }
}
