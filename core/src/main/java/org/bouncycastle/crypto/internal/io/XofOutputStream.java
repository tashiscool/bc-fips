/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.io;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.internal.Xof;

public class XofOutputStream
    extends UpdateOutputStream
{
    private final String algorithmName;
    private final boolean isApprovedMode;

    protected Xof digest;

    public XofOutputStream(
        Xof digest)
    {
        this.algorithmName = digest.getAlgorithmName();
        this.isApprovedMode = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.digest = digest;
    }

    public void write(int b)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        digest.update((byte)b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws IOException
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        digest.update(b, off, len);
    }

    public final int getOutput(byte[] output, int off, int outLen)
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        return digest.doFinal(output, off, outLen);
    }

    public void reset()
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        digest.reset();
    }
}
