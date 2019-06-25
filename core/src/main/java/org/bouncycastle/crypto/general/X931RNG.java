package org.bouncycastle.crypto.general;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.util.encoders.Hex;

class X931RNG
{
    private static final long       BLOCK64_RESEED_MAX = 1L << (16 - 1);
    private static final long       BLOCK128_RESEED_MAX = 1L << (24 - 1);
    private static final int        BLOCK64_MAX_BITS_REQUEST = 1 << (13 - 1);
    private static final int        BLOCK128_MAX_BITS_REQUEST = 1 << (19 - 1);

    private final static Map<String, byte[][]> kats = new HashMap<String, byte[][]>();

    static
    {
        kats.put("AES", new byte[][] { Hex.decode("f7d36762b9915f1ed585eb8e91700eb2"), Hex.decode("259e67249288597a4d61e7c0e690afae"), Hex.decode("35cc0ea481fc8a4f5f05c7d4667233b2"), Hex.decode("15f013af5a8e9df9a8e37500edaeac43") });
        kats.put("DESede", new byte[][] { Hex.decode("ef16ec643e5db5892cbc6eabba310b3410e6f8759e3e382c"), Hex.decode("55df103deaf68dc4"), Hex.decode("96d872b9122c5e74"), Hex.decode("9c960bb9662ce6de") });
    }

    private BlockCipher engine;
    private EntropySource entropySource;

    private final byte[] DT;
    private final byte[] I;
    private final byte[] R;;

    private byte[] V;

    private long reseedCounter = 1;

    /**
     *
     * @param engine
     * @param entropySource
     */
    public X931RNG(BlockCipher engine, byte[] dateTimeVector, EntropySource entropySource)
    {
        this.engine = engine;
        this.entropySource = entropySource;

        this.DT = new byte[engine.getBlockSize()];

        System.arraycopy(dateTimeVector, 0, DT, 0, DT.length);

        this.I = new byte[engine.getBlockSize()];
        this.R = new byte[engine.getBlockSize()];
    }

    /**
     * Return the block size (in bits) of the DRBG.
     *
     * @return the number of bits produced on each internal round of the DRBG.
     */
    public int getBlockSize()
    {
        return engine.getBlockSize() * 8;
    }

    /**
     * Populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    int generate(byte[] output, boolean predictionResistant)
    {
        if (R.length == 8) // 64 bit block size
        {
            if (reseedCounter > BLOCK64_RESEED_MAX)
            {
                return -1;
            }

            if (isTooLarge(output, BLOCK64_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + BLOCK64_MAX_BITS_REQUEST);
            }
        }
        else
        {
            if (reseedCounter > BLOCK128_RESEED_MAX)
            {
                return -1;
            }

            if (isTooLarge(output, BLOCK128_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + BLOCK128_MAX_BITS_REQUEST);
            }
        }
        
        if (predictionResistant || V == null)
        {
            V = getEntropy();
        }

        int m = output.length / R.length;

        for (int i = 0; i < m; i++)
        {
            engine.processBlock(DT, 0, I, 0);
            process(R, I, V);
            process(V, R, I);

            System.arraycopy(R, 0, output, i * R.length, R.length);

            increment(DT);
        }

        int bytesToCopy = (output.length - m * R.length);

        if (bytesToCopy > 0)
        {
            engine.processBlock(DT, 0, I, 0);
            process(R, I, V);
            process(V, R, I);

            System.arraycopy(R, 0, output, m * R.length, bytesToCopy);

            increment(DT);
        }

        reseedCounter++;

        return output.length;
    }

    /**
     * Reseed the RNG.
     */
    void reseed()
    {
        V = getEntropy();
        reseedCounter = 1;
    }

    private byte[] getEntropy()
    {
        byte[] tmp = entropySource.getEntropy();

        if (tmp.length != engine.getBlockSize())
        {
            throw new IllegalStateException("Insufficient entropy provided by entropy source");
        }

        return tmp;
    }

    private void process(byte[] res, byte[] a, byte[] b)
    {
        for (int i = 0; i != res.length; i++)
        {
            res[i] = (byte)(a[i] ^ b[i]);
        }

        engine.processBlock(res, 0, res, 0);
    }

    private void increment(byte[] val)
    {
        for (int i = val.length - 1; i >= 0; i--)
        {
            if (++val[i] != 0)
            {
                break;
            }
        }
    }
    
    private static boolean isTooLarge(byte[] bytes, int maxBytes)
    {
        return bytes != null && bytes.length > maxBytes;
    }

//    public VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm)
//    {
//        return new VariantInternalKatTest(algorithm)
//        {
//            @Override
//            void evaluate()
//                throws Exception
//            {
//                String algorithmName = engine.getAlgorithmName();
//                BlockCipher oldEngine = engine;
//                EntropySource oldEntropySource = entropySource;
//                byte[] oldDT = DT.clone();
//                byte[] oldV = V;
//                long oldReseedCounter = reseedCounter;
//
//                try
//                {
//                    if (algorithmName.equals("AES"))
//                    {
//                        engine = FipsAES.ENGINE_PROVIDER.createEngine();
//                    }
//                    else if (algorithmName.equals("DESede"))
//                    {
//                        engine = FipsTripleDES.ENGINE_PROVIDER.createEngine();
//                    }
//                    else
//                    {
//                        fail("Unknown algorithm in KAT");
//                    }
//
//
//                    byte[][] katV = kats.get(algorithmName);
//
//                    engine.init(true, new KeyParameter(katV[0]));
//
//                    System.arraycopy(katV[1], 0, DT, 0, DT.length);
//                    entropySource = new FixedEntropySourceProvider(katV[2], false).get(engine.getBlockSize() * 8);
//
//                    reseed();
//
//                    byte[] res = new byte[DT.length];
//
//                    generate(res, false);
//
//                    if (!Arrays.areEqual(katV[3], res))
//                    {
//                        fail("KAT test failed");
//                    }
//
//                }
//                finally
//                {
//                    engine = oldEngine;
//                    entropySource = oldEntropySource;
//                    System.arraycopy(oldDT, 0, DT, 0, DT.length);
//                    V = oldV;
//                    reseedCounter = oldReseedCounter;
//                }
//            }
//        };
//    }
}
