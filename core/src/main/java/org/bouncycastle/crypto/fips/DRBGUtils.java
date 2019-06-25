/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import java.util.Hashtable;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

class DRBGUtils
{
    static final Hashtable maxSecurityStrengths = new Hashtable();

    static
    {
        maxSecurityStrengths.put("SHA-1", Integers.valueOf(128));

        maxSecurityStrengths.put("SHA-224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-256", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-384", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512", Integers.valueOf(256));

        maxSecurityStrengths.put("SHA-512/224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-512/256", Integers.valueOf(256));
    }

    static int getMaxSecurityStrength(Digest d)
    {
        return ((Integer)maxSecurityStrengths.get(d.getAlgorithmName())).intValue();
    }

    static int getMaxSecurityStrength(Mac m)
    {
        String name = m.getAlgorithmName();

        return ((Integer)maxSecurityStrengths.get(name.substring(0, name.indexOf("/")))).intValue();
    }

    /**
     * Used by both Dual EC and Hash.
     */
    static byte[] hash_df(Digest digest, byte[] seedMaterial, int seedLength)
    {
         // 1. temp = the Null string.
        // 2. .
        // 3. counter = an 8-bit binary value representing the integer "1".
        // 4. For i = 1 to len do
        // Comment : In step 4.1, no_of_bits_to_return
        // is used as a 32-bit string.
        // 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
        // input_string).
        // 4.2 counter = counter + 1.
        // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
        // 6. Return SUCCESS and requested_bits.
        byte[] temp = new byte[(seedLength + 7) / 8];

        int len = temp.length / digest.getDigestSize();
        int counter = 1;

        byte[] dig = new byte[digest.getDigestSize()];

        for (int i = 0; i <= len; i++)
        {
            digest.update((byte)counter);

            digest.update((byte)(seedLength >> 24));
            digest.update((byte)(seedLength >> 16));
            digest.update((byte)(seedLength >> 8));
            digest.update((byte)seedLength);

            digest.update(seedMaterial, 0, seedMaterial.length);

            digest.doFinal(dig, 0);

            int bytesToCopy = ((temp.length - i * dig.length) > dig.length)
                    ? dig.length
                    : (temp.length - i * dig.length);
            System.arraycopy(dig, 0, temp, i * dig.length, bytesToCopy);

            counter++;
        }

        // do a left shift to get rid of excess bits.
        if (seedLength % 8 != 0)
        {
            int shift = 8 - (seedLength % 8);
            int carry = 0;

            for (int i = 0; i != temp.length; i++)
            {
                int b = temp[i] & 0xff;
                temp[i] = (byte)((b >>> shift) | (carry << (8 - shift)));
                carry = b;
            }
        }

        return temp;
    }

    static boolean isTooLarge(byte[] bytes, int maxBytes)
    {
        return bytes != null && bytes.length > maxBytes;
    }


    /**
     * For self testing
     */
    static class LyingEntropySource
        implements EntropySource
    {
        private final int entropySize;

        LyingEntropySource(int entropySize)
        {
            this.entropySize = entropySize;
        }

        public boolean isPredictionResistant()
        {
            return false;
        }

        public byte[] getEntropy()
        {
            return new byte[2];
        }

        public int entropySize()
        {
            return entropySize;
        }
    }

    // for self testing
    static class KATEntropyProvider
        extends FixedEntropySourceProvider
    {
        KATEntropyProvider()
        {
            super(
                Hex.decode(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
                        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" +
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
                        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), true);
        }
    }
}
