package org.bouncycastle.crypto.internal.wrappers;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;

abstract class SP80038FWrapper
    implements Wrapper
{
    protected static final byte[]    ivKW = {
                                  (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6,
                                  (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6 };
    protected static final byte[]    ivKWP = {
                              (byte)0xa6, (byte)0x59, (byte)0x59, (byte)0xa6 };

    protected final boolean     wrapCipherMode;
    protected final BlockCipher engine;
    protected final int         delta;
    protected final byte[]      iv;

    protected KeyParameter    param;
    protected boolean         forWrapping;

    protected SP80038FWrapper(BlockCipher engine, byte[] iv, boolean useReverseDirection)
    {
        this.engine = engine;
        this.wrapCipherMode = (useReverseDirection) ? false : true;
        this.delta = engine.getBlockSize() / 2;
        this.iv = new byte[iv.length > delta ? delta : iv.length];
        System.arraycopy(iv, 0, this.iv, 0, this.iv.length);
    }

    public void init(
        boolean             forWrapping,
        CipherParameters    param)
    {
        this.forWrapping = forWrapping;

        if (param instanceof KeyParameter)
        {
            this.param = (KeyParameter)param;
        }
        else if (param instanceof ParametersWithIV)
        {
            byte[] newIv =  ((ParametersWithIV)param).getIV();
            if (newIv.length != iv.length)
            {
               throw new IllegalArgumentException("IV not equal to " + ivKWP.length);
            }
            this.param = (KeyParameter)((ParametersWithIV) param).getParameters();
            System.arraycopy(newIv, 0, iv, 0, iv.length);
        }
    }

    protected byte[] W(int n, byte[] block)
    {
        byte[]  buf = new byte[engine.getBlockSize()];

        engine.init(wrapCipherMode, param);

        for (int j = 0; j != 6; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                System.arraycopy(block, 0, buf, 0, delta);
                System.arraycopy(block, delta * i, buf, delta, delta);
                engine.processBlock(buf, 0, buf, 0);

                int t = n * j + i;
                for (int k = 1; t != 0; k++)
                {
                    byte    v = (byte)t;

                    buf[delta - k] ^= v;

                    t >>>= 8;
                }

                System.arraycopy(buf, 0, block, 0, delta);
                System.arraycopy(buf, delta, block, delta * i, delta);
            }
        }

        return block;
    }

    protected void invW(int n, byte[] block, byte[] a)
    {
        byte[]  buf = new byte[engine.getBlockSize()];

        engine.init(!wrapCipherMode, param);

        n = n - 1;

        for (int j = 5; j >= 0; j--)
        {
            for (int i = n; i >= 1; i--)
            {
                System.arraycopy(a, 0, buf, 0, delta);
                System.arraycopy(block, delta * (i - 1), buf, delta, delta);

                int t = n * j + i;
                for (int k = 1; t != 0; k++)
                {
                    byte    v = (byte)t;

                    buf[delta - k] ^= v;

                    t >>>= 8;
                }

                engine.processBlock(buf, 0, buf, 0);
                System.arraycopy(buf, 0, a, 0, delta);
                System.arraycopy(buf, delta, block, delta * (i - 1), delta);
            }
        }
    }
}
