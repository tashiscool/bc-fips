package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.OutputMACCalculator;
import org.bouncycastle.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode OutputMACCalculator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this calculator.
 */
public abstract class FipsOutputMACCalculator<T>
    implements OutputMACCalculator<T>
{
    // package protect construction
    FipsOutputMACCalculator()
    {
    }

    public byte[] getMAC()
    {
        byte[] res = new byte[this.getMACSize()];

        getMAC(res, 0);

        return res;
    }

    public abstract T getParameters();

    public abstract int getMACSize();

    public abstract UpdateOutputStream getMACStream();

    public abstract int getMAC(byte[] output, int off);

    public abstract void reset();
}
