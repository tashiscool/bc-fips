/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.params;

import org.bouncycastle.crypto.internal.CipherParameters;

public class ParametersWithIV
    implements CipherParameters
{
    private byte[]              iv;
    private CipherParameters    parameters;

    public ParametersWithIV(
        CipherParameters    parameters,
        byte[]              iv)
    {
        this(parameters, iv, 0, iv.length);
    }

    public ParametersWithIV(
        CipherParameters    parameters,
        byte[]              iv,
        int                 ivOff,
        int                 ivLen)
    {
        this.iv = new byte[ivLen];
        this.parameters = parameters;

        System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
    }

    public byte[] getIV()
    {
        return iv;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
