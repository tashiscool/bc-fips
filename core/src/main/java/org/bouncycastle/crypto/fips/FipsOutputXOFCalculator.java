package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.OutputXOFCalculator;
import org.bouncycastle.crypto.UpdateOutputStream;

/**
 * Base class for a FIPS extendable output function calculator.
 *
 * @param <T> The parameters class for this verifier.
 */
public abstract class FipsOutputXOFCalculator<T extends FipsParameters>
    implements OutputXOFCalculator<T>
{
    public byte[] getFunctionOutput(int outLen)
    {
        byte[] output = new byte[outLen];

        getFunctionOutput(output, 0, output.length);

        return output;
    }

    public abstract T getParameters();

    public abstract UpdateOutputStream getFunctionStream();

    public abstract int getFunctionOutput(byte[] output, int off, int outLen);

    public abstract void reset();
}
