/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.io;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.internal.Digest;

public class DigestOutputStream
    extends UpdateOutputStream
{
    private final String algorithmName;
    private final boolean isApprovedMode;

    protected Digest digest;

    public DigestOutputStream(
        Digest          digest)
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

    public final byte[] getDigest()
    {
        Utils.approvedModeCheck(isApprovedMode, algorithmName);

        byte[] res = new byte[digest.getDigestSize()];
        
        digest.doFinal(res, 0);
        
        return res;
    }
}
