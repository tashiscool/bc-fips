package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.MACOperatorFactory;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.io.MacOutputStream;

/**
 * Base class for the approved mode MACOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsMACOperatorFactory<T extends AuthenticationParameters>
    implements MACOperatorFactory<T>
{
    // package protect constructor
    FipsMACOperatorFactory()
    {
         FipsStatus.isReady();
    }

    public final FipsOutputMACCalculator<T> createOutputMACCalculator(SymmetricKey key, final T parameters)
    {
        final Mac mac = createMAC(key, parameters);

        return new FipsOutputMACCalculator<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public int getMACSize()
            {
                return mac.getMacSize();
            }

            public org.bouncycastle.crypto.UpdateOutputStream getMACStream()
            {
                return new MacOutputStream(mac);
            }

            public int getMAC(byte[] output, int off)
            {
                return mac.doFinal(output, off);
            }

            public void reset()
            {
                mac.reset();
            }
        };
    }

    protected abstract int calculateMACSize(T parameters);

    protected abstract Mac createMAC(SymmetricKey key, T parameters);
}
