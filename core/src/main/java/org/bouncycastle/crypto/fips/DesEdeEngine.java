/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.OutputLengthException;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;

/**
 * a class that provides a basic DESede (or Triple DES) engine.
 */
class DesEdeEngine
    extends DesBase
    implements BlockCipher
{
    private static final KeyParameter ZERO_KEY = new KeyParameterImpl(new byte[24]);

    private static final int MAX_BLOCK_COUNT = 1 << 20;

    protected static final int  BLOCK_SIZE = 8;

    private int[]               workingKey1 = null;
    private int[]               workingKey2 = null;
    private int[]               workingKey3 = null;

    private boolean             forEncryption;
    private boolean             firstBlock;
    private int                 blockCount;

    /**
     * standard constructor.
     */
    public DesEdeEngine()
    {
    }

    /**
     * initialise a DESede cipher.
     *
     * @param encrypting whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           encrypting,
        CipherParameters  params)
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("invalid parameter passed to DESede init - " + params.getClass().getName());
        }

        byte[] keyMaster = ((KeyParameter)params).getKey();

        if (keyMaster.length != 24 && keyMaster.length != 16)
        {
            throw new IllegalArgumentException("key size must be 16 or 24 bytes.");
        }

        this.forEncryption = encrypting;

        byte[] key1 = new byte[8];
        System.arraycopy(keyMaster, 0, key1, 0, key1.length);
        workingKey1 = generateWorkingKey(encrypting, key1);

        byte[] key2 = new byte[8];
        System.arraycopy(keyMaster, 8, key2, 0, key2.length);
        workingKey2 = generateWorkingKey(!encrypting, key2);

        if (keyMaster.length == 24)
        {
            byte[] key3 = new byte[8];
            System.arraycopy(keyMaster, 16, key3, 0, key3.length);
            workingKey3 = generateWorkingKey(encrypting, key3);
        }
        else    // 16 byte key
        {
            workingKey3 = workingKey1;
        }

        // these shouldn't be changed by reset as they are properties of the key.
        blockCount = 0;
        firstBlock = true;
    }

    public String getAlgorithmName()
    {
        return "DESede";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (workingKey1 == null)
        {
            throw new IllegalStateException("DESede engine not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        byte[] temp = new byte[BLOCK_SIZE];

        if (forEncryption)
        {
            if (workingKey1 == workingKey3)
            {
                if (blockCount >= MAX_BLOCK_COUNT)
                {
                    throw new IllegalStateException("attempt to process more than " + MAX_BLOCK_COUNT + " blocks with 2-Key TripleDES");
                }
            }
            else
            {
                if (blockCount == 0 && !firstBlock)
                {
                    throw new IllegalStateException("attempt to process too many blocks with 3-Key TripleDES");
                }
                firstBlock = false;
            }

            desFunc(workingKey1, in, inOff, temp, 0);
            desFunc(workingKey2, temp, 0, temp, 0);
            desFunc(workingKey3, temp, 0, out, outOff);
        }
        else
        {
            desFunc(workingKey3, in, inOff, temp, 0);
            desFunc(workingKey2, temp, 0, temp, 0);
            desFunc(workingKey1, temp, 0, out, outOff);
        }

        blockCount++;

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        this.init(true, ZERO_KEY);    // ZEROIZE: clear key schedule on de-allocation
    }
}
