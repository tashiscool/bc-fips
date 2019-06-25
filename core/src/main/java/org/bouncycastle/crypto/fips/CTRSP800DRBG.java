package org.bouncycastle.crypto.fips;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * A SP800-90A CTR DRBG.
 */
class CTRSP800DRBG
    implements SP80090DRBG
{
    private static final long TDEA_RESEED_MAX = 1L << (32 - 1);
    private static final long AES_RESEED_MAX = 1L << (48 - 1);
    private static final int TDEA_MAX_BITS_REQUEST = 1 << (13 - 1);
    private static final int AES_MAX_BITS_REQUEST = 1 << (19 - 1);

    private final static Map<String, byte[][]> kats = new HashMap<String, byte[][]>();

    private final static Map<String, byte[][]> reseedKats = new HashMap<String, byte[][]>();
    private final static Map<String, byte[][]> reseedValues = new HashMap<String, byte[][]>();

    static
    {
        kats.put("TRIPLEDES", new byte[][]{
            Hex.decode("09b2711937c5fc9fdf6f7e070625b41f74916ddb93b9f7a7c90091f86cdf2003a052e8d17bc37d86"),
            Hex.decode("b5c3c811e17247830be34f9461bf991401edbe99bc0dd6668b5d3f2501d2659bf99da71e38979e75")});

        kats.put("AES-128", new byte[][]{
            Hex.decode("314069e227a6e4c59c402ac0f9189f921ef19673d16b3fd401ded2f3b8b1d19a1c3b11f948ba8e2a"),
            Hex.decode("36ccfd81909865e88091079bbd408e9943dd3bedf8e7521e43cd639fed11f482bb17a794ed0265f1")});

        kats.put("AES-192", new byte[][]{
            Hex.decode("7ee353634fb8bd87bd4a2b292db7a049615bb8ae6a887efb8e81af7124453dac21949cfb51dd065f"),
            Hex.decode("8861d7165d9983a987e4ac39b9013ae41377f2134e5c7b57d6f8a3653e0ee616f0ddc9e11d85a8fd")});

        kats.put("AES-256", new byte[][]{
            Hex.decode("f5771b72bb3c3ceeea5d4327159f7bcf5d3aed67adaa039528b3d5f846961700734ac1aa5d401709"),
            Hex.decode("a6b09617644ea00b797ce09060d23682b89a09c293fb5fac71ba77943421a7559557bd957bce64c9")});

        reseedValues.put("TRIPLEDES", new byte[][]{
            Hex.decode("0102030405060708090a0b0c0d0e0f101112131415"),
            Hex.decode("0807060504030201")});

        reseedValues.put("AES-128", new byte[][]{
            Hex.decode("0102030405060708090a0b0c0d0e0f10"),
            Hex.decode("100f0e0d0c0b0a090807060504030201")});

        reseedValues.put("AES-192", new byte[][]{
            Hex.decode("0102030405060708090a0b0c0d0e0f101112131415161718"),
            Hex.decode("100f0e0d0c0b0a090807060504030201")});

        reseedValues.put("AES-256", new byte[][]{
            Hex.decode("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"),
            Hex.decode("100f0e0d0c0b0a090807060504030201")});

        reseedKats.put("TRIPLEDES", new byte[][]{
            Hex.decode("48ce7cefb4ec0f4a5a3b50c09a309675a9827404e01e0adff50a6d8d895d0308f6fffaf5e8159a8a"),
            Hex.decode("19d8a900cf51f131070cbbf22a7028edb42d79c836feb0a270e6703bf7d64ffa7bab66922bc7597b")});

        reseedKats.put("AES-128", new byte[][]{
            Hex.decode("af649344a18257a1448aca5e7014c784cf01618ac354a4dd9b63b83f10fd4d31eff645b737619fd7"),
            Hex.decode("c63ff00c3f966108d53270633a945b87fd11d8344946589f1533617323895593229d060c0b25f53e")});

        reseedKats.put("AES-192", new byte[][]{
            Hex.decode("544c683bd1538f349b62135813dc752ee329244ec83e037039dc35beb12a28ea505cdb81ec4bd61e"),
            Hex.decode("58dda13ba129e5ea009c8d0dac7cc5c998b84d52f759acfffa9bdd08d7cdbedc185114e270679e99")});

        reseedKats.put("AES-256", new byte[][]{
            Hex.decode("e20e7e3e5fc4876ac58b412c20b0cd173e0c934762f32d558f84c7a533efcee1b1571253afe18551"),
            Hex.decode("bae2554712e8143be922d97125c7b88fd768dd7c359fc1fe413f6ba5cb83892fe4a407c8aec04762")});
    }

    private EntropySource _entropySource;
    private BlockCipher _engine;
    private int _keySizeInBits;
    private int _seedLength;
    private boolean _isTDEA = false;
    private int _securityStrength;

    // internal state
    private byte[] _Key;
    private byte[] _V;
    private long _reseedCounter = 0;


    /**
     * Construct a SP800-90A CTR DRBG.
     * <p>
     * Minimum entropy requirement is the security strength requested.
     * </p>
     * @param engine underlying block cipher to use to support DRBG
     * @param keySizeInBits size of the key to use with the block cipher.
     * @param securityStrength security strength required (in bits)
     * @param entropySource source of entropy to use for seeding/reseeding.
     * @param personalizationString personalization string to distinguish this DRBG (may be null).
     * @param nonce nonce to further distinguish this DRBG (may be null).
     */
    public CTRSP800DRBG(BlockCipher engine, int keySizeInBits, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        _engine = engine;
        _keySizeInBits = keySizeInBits;
        _seedLength = keySizeInBits + engine.getBlockSize() * 8;
        _isTDEA = isTDEA(engine);

        init(securityStrength, entropySource, personalizationString, nonce);
    }

    private void init(int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        if (securityStrength > 256)
        {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }

        if (getMaxSecurityStrength(_engine, _keySizeInBits) < securityStrength)
        {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }

        if (entropySource.entropySize() < securityStrength)
        {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }

        _entropySource = entropySource;
        _securityStrength = securityStrength;

        CTR_DRBG_Instantiate_algorithm(personalizationString, nonce);
    }

    private void CTR_DRBG_Instantiate_algorithm(byte[] personalisationString, byte[] nonce)
    {
        byte[] entropy = getEntropy();  // Get_entropy_input
        byte[] input = Arrays.concatenate(entropy, nonce, personalisationString);
        Arrays.fill(entropy, (byte)0);

        byte[] seedMaterial = Block_Cipher_df(input, _seedLength);
        Arrays.fill(input, (byte)0);

        int outlen = _engine.getBlockSize();

        _Key = new byte[getExpandedKeySizeInBytes()];
        _V = new byte[outlen];

        expandKey(_Key);

        // _Key & _V are modified by this call
        CTR_DRBG_Update(seedMaterial);
        Arrays.fill(seedMaterial, (byte)0);

        _reseedCounter = 1;
    }

    private void CTR_DRBG_Update(byte[] seedMaterial)
    {
        byte[] temp = new byte[seedMaterial.length];
        byte[] outputBlock = new byte[_engine.getBlockSize()];

        int i = 0;
        int outLen = _engine.getBlockSize();

        _engine.init(true, new KeyParameterImpl(_Key));
        while (i * outLen < seedMaterial.length)
        {
            addOneTo(_V);
            _engine.processBlock(_V, 0, outputBlock, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                ? outLen : (temp.length - i * outLen);

            System.arraycopy(outputBlock, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }

        Arrays.fill(outputBlock, (byte)0);

        XOR(temp, seedMaterial, temp, 0);
        System.arraycopy(temp, 0, _Key, 0, getKeySizeInBytes());
        System.arraycopy(temp, getKeySizeInBytes(), _V, 0, _V.length);
        Arrays.fill(temp, (byte)0);

        expandKey(_Key);
    }

    private void CTR_DRBG_Reseed_algorithm(byte[] additionalInput)
    {
        byte[] entropy = getEntropy();
        byte[] input = Arrays.concatenate(entropy, additionalInput);
        Arrays.fill(entropy, (byte)0);

        byte[] seedMaterial = Block_Cipher_df(input, _seedLength);
        Arrays.fill(input, (byte)0);

        // _Key & _V are modified by this call
        CTR_DRBG_Update(seedMaterial);
        Arrays.fill(seedMaterial, (byte)0);

        _reseedCounter = 1;
    }

    private void XOR(byte[] out, byte[] a, byte[] b, int bOff)
    {
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte)(a[i] ^ b[i + bOff]);
        }
    }

    private void addOneTo(byte[] longer)
    {
        int carry = 1;
        for (int i = 1; i <= longer.length; i++) // warning
        {
            int res = (longer[longer.length - i] & 0xff) + carry;
            carry = (res > 0xff) ? 1 : 0;
            longer[longer.length - i] = (byte)res;
        }
    }

    // -- Internal state migration ---

    private static final byte[] K_BITS = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    // 1. If (number_of_bits_to_return > max_number_of_bits), then return an
    // ERROR_FLAG.
    // 2. L = len (input_string)/8.
    // 3. N = number_of_bits_to_return/8.
    // Comment: L is the bitstring represention of
    // the integer resulting from len (input_string)/8.
    // L shall be represented as a 32-bit integer.
    //
    // Comment : N is the bitstring represention of
    // the integer resulting from
    // number_of_bits_to_return/8. N shall be
    // represented as a 32-bit integer.
    //
    // 4. S = L || N || input_string || 0x80.
    // 5. While (len (S) mod outlen)
    // Comment : Pad S with zeros, if necessary.
    // 0, S = S || 0x00.
    //
    // Comment : Compute the starting value.
    // 6. temp = the Null string.
    // 7. i = 0.
    // 8. K = Leftmost keylen bits of 0x00010203...1D1E1F.
    // 9. While len (temp) < keylen + outlen, do
    //
    // IV = i || 0outlen - len (i).
    //
    // 9.1
    //
    // temp = temp || BCC (K, (IV || S)).
    //
    // 9.2
    //
    // i = i + 1.
    //
    // 9.3
    //
    // Comment : i shall be represented as a 32-bit
    // integer, i.e., len (i) = 32.
    //
    // Comment: The 32-bit integer represenation of
    // i is padded with zeros to outlen bits.
    //
    // Comment: Compute the requested number of
    // bits.
    //
    // 10. K = Leftmost keylen bits of temp.
    //
    // 11. X = Next outlen bits of temp.
    //
    // 12. temp = the Null string.
    //
    // 13. While len (temp) < number_of_bits_to_return, do
    //
    // 13.1 X = Block_Encrypt (K, X).
    //
    // 13.2 temp = temp || X.
    //
    // 14. requested_bits = Leftmost number_of_bits_to_return of temp.
    //
    // 15. Return SUCCESS and requested_bits.
    private byte[] Block_Cipher_df(byte[] inputString, int bitLength)
    {
        int outLen = _engine.getBlockSize();
        int L = inputString.length; // already in bytes
        int N = bitLength / 8;
        // 4 S = L || N || inputstring || 0x80
        int sLen = 4 + 4 + L + 1;
        int blockLen = ((sLen + outLen - 1) / outLen) * outLen;
        byte[] S = new byte[blockLen];
        copyIntToByteArray(S, L, 0);
        copyIntToByteArray(S, N, 4);
        System.arraycopy(inputString, 0, S, 8, L);
        S[8 + L] = (byte)0x80;
        // S already padded with zeros

        byte[] temp = new byte[getKeySizeInBytes() + outLen];
        byte[] bccOut = new byte[outLen];

        byte[] IV = new byte[outLen];

        int i = 0;
        byte[] K = new byte[getExpandedKeySizeInBytes()];
        System.arraycopy(K_BITS, 0, K, 0, getKeySizeInBytes());

        expandKey(K);

        KeyParameter bccKey = new KeyParameterImpl(K);

        while (i * outLen * 8 < _keySizeInBits + outLen * 8)
        {
            copyIntToByteArray(IV, i, 0);
            BCC(bccOut, bccKey, IV, S);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                ? outLen
                : (temp.length - i * outLen);

            System.arraycopy(bccOut, 0, temp, i * outLen, bytesToCopy);
            ++i;
        }

        Arrays.fill(S, (byte)0);
        Arrays.fill(bccOut, (byte)0);
        Arrays.fill(IV, (byte)0);

        byte[] X = new byte[outLen];
        System.arraycopy(temp, 0, K, 0, getKeySizeInBytes());
        System.arraycopy(temp, getKeySizeInBytes(), X, 0, X.length);
        Arrays.fill(temp, (byte)0);

        expandKey(K);

        temp = new byte[bitLength / 2];

        i = 0;
        _engine.init(true, new KeyParameterImpl(K));

        while (i * outLen < temp.length)
        {
            _engine.processBlock(X, 0, X, 0);

            int bytesToCopy = ((temp.length - i * outLen) > outLen)
                ? outLen
                : (temp.length - i * outLen);

            System.arraycopy(X, 0, temp, i * outLen, bytesToCopy);
            i++;
        }

        Arrays.fill(X, (byte)0);
        Arrays.fill(K, (byte)0);

        return temp;
    }

    /*
    * 1. chaining_value = 0^outlen
    *    . Comment: Set the first chaining value to outlen zeros.
    * 2. n = len (data)/outlen.
    * 3. Starting with the leftmost bits of data, split the data into n blocks of outlen bits
    *    each, forming block(1) to block(n).
    * 4. For i = 1 to n do
    * 4.1 input_block = chaining_value ^ block(i) .
    * 4.2 chaining_value = Block_Encrypt (Key, input_block).
    * 5. output_block = chaining_value.
    * 6. Return output_block.
     */
    private void BCC(byte[] bccOut, KeyParameter k, byte[] iV, byte[] data)
    {
        int outlen = _engine.getBlockSize();
        byte[] chainingValue = new byte[outlen]; // initial values = 0
        int n = data.length / outlen;

        byte[] inputBlock = new byte[outlen];

        _engine.init(true, k);

        _engine.processBlock(iV, 0, chainingValue, 0);

        for (int i = 0; i < n; i++)
        {
            XOR(inputBlock, chainingValue, data, i * outlen);
            _engine.processBlock(inputBlock, 0, chainingValue, 0);
        }

        System.arraycopy(chainingValue, 0, bccOut, 0, bccOut.length);
    }

    private void copyIntToByteArray(byte[] buf, int value, int offSet)
    {
        buf[offSet + 0] = ((byte)(value >> 24));
        buf[offSet + 1] = ((byte)(value >> 16));
        buf[offSet + 2] = ((byte)(value >> 8));
        buf[offSet + 3] = ((byte)(value));
    }

    /**
     * Return the block size (in bits) of the DRBG.
     *
     * @return the number of bits produced on each internal round of the DRBG.
     */
    public int getBlockSize()
    {
        return _V.length * 8;
    }

    /**
     * Return the security strength of the DRBG.
     *
     * @return the security strength (in bits) of the DRBG.
     */
    public int getSecurityStrength()
    {
        return _securityStrength;
    }

    /**
     * Populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param additionalInput additional input to be added to the DRBG in this step.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        if (predictionResistant)
        {
            CTR_DRBG_Reseed_algorithm(additionalInput);
            additionalInput = null;
        }

        if (_isTDEA)
        {
            if (_reseedCounter > TDEA_RESEED_MAX)
            {
                return -1;
            }

            if (DRBGUtils.isTooLarge(output, TDEA_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + TDEA_MAX_BITS_REQUEST);
            }
        }
        else
        {
            if (_reseedCounter > AES_RESEED_MAX)
            {
                return -1;
            }

            if (DRBGUtils.isTooLarge(output, AES_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + AES_MAX_BITS_REQUEST);
            }
        }

        byte[] seedMaterial;
        if (additionalInput != null)
        {
            seedMaterial = Block_Cipher_df(additionalInput, _seedLength);

            // _Key & _V are modified by this call
            CTR_DRBG_Update(seedMaterial);
        }
        else
        {
            seedMaterial = new byte[_seedLength];
        }

        byte[] out = new byte[_V.length];

        _engine.init(true, new KeyParameterImpl(_Key));

        for (int i = 0; i <= output.length / out.length; i++)
        {
            int bytesToCopy = ((output.length - i * out.length) > out.length)
                ? out.length
                : (output.length - i * _V.length);

            if (bytesToCopy != 0)
            {
                addOneTo(_V);

                _engine.processBlock(_V, 0, out, 0);

                System.arraycopy(out, 0, output, i * out.length, bytesToCopy);
            }
        }

        // _Key & _V are modified by this call
        CTR_DRBG_Update(seedMaterial);
        Arrays.fill(seedMaterial, (byte)0);

        _reseedCounter++;

        return output.length * 8;
    }

    /**
     * Reseed the DRBG.
     *
     * @param additionalInput additional input to be added to the DRBG in this step.
     */
    public void reseed(byte[] additionalInput)
    {
        CTR_DRBG_Reseed_algorithm(additionalInput);
    }

    private byte[] getEntropy()
    {
        byte[] entropy = _entropySource.getEntropy();
        if (entropy == null || entropy.length < (_securityStrength + 7) / 8)
        {
            throw new IllegalStateException("Insufficient entropy provided by entropy source");
        }
        return entropy;
    }

    @Override
    protected void finalize() throws Throwable
    {
        super.finalize();

        Arrays.fill(_Key, (byte)0);
        Arrays.fill(_V, (byte)0);
    }

    public VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm)
    {
        return new VariantInternalKatTest(algorithm)
        {
            @Override
            void evaluate()
                throws Exception
            {
                byte[] origKey = _Key;
                byte[] origV = _V;
                long origReseedCounter = _reseedCounter;
                EntropySource origEntropySource = _entropySource;

                try
                {
                    byte[] personalization = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");
                    byte[] nonce = Hex.decode("2021222324");

                    final int entropyStrength = getMaxSecurityStrength(_engine, _keySizeInBits);

                    byte[][] expected = kats.get(algorithm.getName());

                    init(_securityStrength, new DRBGUtils.KATEntropyProvider().get(entropyStrength), personalization, nonce);

                    byte[] output = new byte[expected[0].length];

                    generate(output, null, true);
                    if (!Arrays.areEqual(expected[0], output))
                    {
                        fail("DRBG Block 1 KAT failure");
                    }

                    output = new byte[expected[1].length];

                    generate(output, null, true);
                    if (!Arrays.areEqual(expected[1], output))
                    {
                        fail("DRBG Block 2 KAT failure");
                    }

                    try
                    {
                        init(_securityStrength, new DRBGUtils.LyingEntropySource(entropyStrength), personalization, nonce);

                        fail("DRBG LyingEntropySource not detected in init");
                    }
                    catch (IllegalStateException e)
                    {
                        if (!e.getMessage().equals("Insufficient entropy provided by entropy source"))
                        {
                            fail("DRBG self test failed init entropy check");
                        }
                    }

                    try
                    {
                        init(_securityStrength, new DRBGUtils.LyingEntropySource(20), personalization, nonce);

                        fail("DRBG insufficient EntropySource not detected");
                    }
                    catch (IllegalArgumentException e)
                    {
                        if (!e.getMessage().equals("Not enough entropy for security strength required"))
                        {
                            fail("DRBG self test failed init entropy check");
                        }
                    }

                    try
                    {
                        _entropySource = new DRBGUtils.LyingEntropySource(entropyStrength);

                        reseed(null);

                        fail("DRBG LyingEntropySource not detected in reseed");
                    }
                    catch (IllegalStateException e)
                    {
                        if (!e.getMessage().equals("Insufficient entropy provided by entropy source"))
                        {
                            fail("DRBG self test failed reseed entropy check");
                        }
                    }

                    try
                    {
                        init(entropyStrength + 1, new DRBGUtils.KATEntropyProvider().get(entropyStrength), personalization, nonce);

                        fail("DRBG successful initialise with too high security strength");
                    }
                    catch (IllegalArgumentException e)
                    {
                        if (!e.getMessage().equals("Requested security strength is not supported by the derivation function"))
                        {
                            fail("DRBG self test failed init security strength check");
                        }
                    }
                }
                finally
                {
                    _Key = origKey;
                    _V = origV;
                    _reseedCounter = origReseedCounter;
                    _entropySource = origEntropySource;
                }
            }
        };
    }

    public VariantInternalKatTest createReseedSelfTest(FipsAlgorithm algorithm)
    {
        return new VariantInternalKatTest(algorithm)
        {
            @Override
            void evaluate()
                throws Exception
            {
                byte[] origKey = _Key;
                byte[] origV = _V;
                long origReseedCounter = _reseedCounter;
                EntropySource origEntropySource = _entropySource;

                try
                {
                    byte[] additionalInput = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");

                    int entropyStrength = getMaxSecurityStrength(_engine, _keySizeInBits);
                    byte[][] expected = reseedKats.get(algorithm.getName());
                    byte[][] internalValues = reseedValues.get(algorithm.getName());

                    {
                        byte[] iv0 = internalValues[0];
                        _Key = new byte[getExpandedKeySizeInBytes()];
                        System.arraycopy(iv0, 0, _Key, 0, iv0.length);
                        expandKey(_Key);
                    }

                    _V = Arrays.clone(internalValues[1]);

                    _entropySource = new DRBGUtils.KATEntropyProvider().get(entropyStrength);

                    reseed(additionalInput);

                    if (_reseedCounter != 1)
                    {
                        fail("DRBG reseedCounter failed to reset");
                    }

                    byte[] output = new byte[expected[0].length];

                    generate(output, null, false);
                    if (!Arrays.areEqual(expected[0], output))
                    {
                        fail("DRBG Block 1 reseed KAT failure");
                    }

                    output = new byte[expected[1].length];

                    generate(output, null, false);
                    if (!Arrays.areEqual(expected[1], output))
                    {
                        fail("DRBG Block 2 reseed KAT failure");
                    }

                    try
                    {
                        _entropySource = new DRBGUtils.LyingEntropySource(entropyStrength);

                        reseed(null);

                        fail("DRBG LyingEntropySource not detected");
                    }
                    catch (IllegalStateException e)
                    {
                        if (!e.getMessage().equals("Insufficient entropy provided by entropy source"))
                        {
                            fail("DRBG self test failed reseed entropy check");
                        }
                    }
                }
                finally
                {
                    _Key = origKey;
                    _V = origV;
                    _reseedCounter = origReseedCounter;
                    _entropySource = origEntropySource;
                }
            }
        };
    }

    private boolean isTDEA(BlockCipher cipher)
    {
        return cipher.getAlgorithmName().equals("DESede") || cipher.getAlgorithmName().equals("TDEA");
    }

    private int getMaxSecurityStrength(BlockCipher cipher, int keySizeInBits)
    {
        if (isTDEA(cipher) && keySizeInBits == 168)
        {
            return 112;
        }
        if (cipher.getAlgorithmName().equals("AES"))
        {
            return keySizeInBits;
        }

        return -1;
    }

    /**
     * Note that the input key must already be large enough to hold its expanded form
     */
    private void expandKey(byte[] key)
    {
        if (_isTDEA)
        {
            // expand key to 192 bits.
            byte[] tmp = new byte[24];
            padKey(key, 0, tmp, 0);
            padKey(key, 7, tmp, 8);
            padKey(key, 14, tmp, 16);
            System.arraycopy(tmp, 0, key, 0, 24);
            Arrays.fill(tmp, (byte)0);
        }
    }

    private int getExpandedKeySizeInBytes()
    {
        return _isTDEA ? 24 : getKeySizeInBytes();
    }

    private int getKeySizeInBytes()
    {
        return (_keySizeInBits + 7) / 8;
    }

    /**
     * Pad out a key for TDEA, setting odd parity for each byte.
     *
     * @param keyMaster
     * @param keyOff
     * @param tmp
     * @param tmpOff
     */
    private void padKey(byte[] keyMaster, int keyOff, byte[] tmp, int tmpOff)
    {
        tmp[tmpOff + 0] = (byte)(keyMaster[keyOff + 0] & 0xfe);
        tmp[tmpOff + 1] = (byte)((keyMaster[keyOff + 0] << 7) | ((keyMaster[keyOff + 1] & 0xfc) >>> 1));
        tmp[tmpOff + 2] = (byte)((keyMaster[keyOff + 1] << 6) | ((keyMaster[keyOff + 2] & 0xf8) >>> 2));
        tmp[tmpOff + 3] = (byte)((keyMaster[keyOff + 2] << 5) | ((keyMaster[keyOff + 3] & 0xf0) >>> 3));
        tmp[tmpOff + 4] = (byte)((keyMaster[keyOff + 3] << 4) | ((keyMaster[keyOff + 4] & 0xe0) >>> 4));
        tmp[tmpOff + 5] = (byte)((keyMaster[keyOff + 4] << 3) | ((keyMaster[keyOff + 5] & 0xc0) >>> 5));
        tmp[tmpOff + 6] = (byte)((keyMaster[keyOff + 5] << 2) | ((keyMaster[keyOff + 6] & 0x80) >>> 6));
        tmp[tmpOff + 7] = (byte)(keyMaster[keyOff + 6] << 1);

        for (int i = tmpOff; i <= tmpOff + 7; i++)
        {
            int b = tmp[i];
            tmp[i] = (byte)((b & 0xfe) |
                ((((b >> 1) ^
                    (b >> 2) ^
                    (b >> 3) ^
                    (b >> 4) ^
                    (b >> 5) ^
                    (b >> 6) ^
                    (b >> 7)) ^ 0x01) & 0x01));
        }
    }
}
