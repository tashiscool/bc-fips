package org.bouncycastle.crypto.fips;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * A SP800-90A HMAC DRBG.
 */
class HMacSP800DRBG
    implements SP80090DRBG
{
    private final static long       RESEED_MAX = 1L << (48 - 1);
    private final static int        MAX_BITS_REQUEST = 1 << (19 - 1);

    private final static Map<String, byte[][]> kats = new HashMap<String, byte[][]>();

    private final static Map<String, byte[][]> reseedKats = new HashMap<String, byte[][]>();
    private final static Map<String, byte[][]> reseedValues = new HashMap<String, byte[][]>();

    static
    {
        kats.put("SHA-1/HMAC", new byte[][] {
            Hex.decode("09e8e2eab9b4acfcea6fc8f8e98a25ff0481ced2ad65e9682e347965529c421b0ee65f1af7f06657"),
            Hex.decode("7982a3a8c3a737407ca1f6f3821f1d1ed1d1acfbf3e6a2d830ee702063ef42992de2b4f5c3157310") });

        kats.put("SHA-224/HMAC", new byte[][] {
            Hex.decode("24eff5d06816cd3da66f7888ca2c80d4416ed1adb35040492b8d1a06cf280382fcd4008f0e7809db"),
            Hex.decode("d014b676e03610a8addf59b25ccf227758b72c7fb218e3308336188352acbe12ac3e4d43837e7320") });

        kats.put("SHA-256/HMAC", new byte[][] {
            Hex.decode("c8eb1ed8c27c86fad174c8445b1a8401735cabd847a533ddf75bb43fe1bed58916ed222d10715dd5"),
            Hex.decode("67cf599a5a80d7cdf6113468e6f1dd66bd4e9864511f5913749511ac56a3f3a75fb0b68c5502444d") });

        kats.put("SHA-384/HMAC", new byte[][] {
            Hex.decode("7a70bad84ceeb34ddfae4fe0e7911f3772b9bcdc95fc373254be4c64282e517e8b5346440d73e6b6"),
            Hex.decode("7d68e490dbc4c0043eb3510ec1cee55b4718bfcfc4e93f3341fa3bbc0513e92ef38f40f2ffe04b4b") });

        kats.put("SHA-512/HMAC", new byte[][] {
            Hex.decode("7223e2b58fb4b987cbd25f0b01a19135ca5cd78ccc16e8e5f8c6efd33fe2a71a97c3c8456fba6507"),
            Hex.decode("e90ee5626d5266cf6b70d118b07a0d4dd06ff0db4a65248628eadb88d9994f8e59a093b4ad217a83") });

        kats.put("SHA-512(224)/HMAC", new byte[][] {
            Hex.decode("0c1563ed502a9e9b33fc3beb8adced92f7440b346f311ffd3727a14d461f9199a6ef3c827a5199fb"),
            Hex.decode("40dc8b5b304cf82ddd4d47c69ba0743b242bddabf393353ed78867b947b2f8e6a553605253b62356") });

        kats.put("SHA-512(256)/HMAC", new byte[][] {
            Hex.decode("a9c1c62095292f475eb8a2a80890f9b3d77b9b42d4ef446881315d3531eccb5430c6659a4fc3c63b"),
            Hex.decode("1c0d60c8a99603ef18588d5c441c9ed2db93b682f810af39dc60296d8ea102505004f9b9fdf3cbc6") });

        reseedValues.put("SHA-1/HMAC", new byte[][]{
            Hex.decode("7bedcd650a8ddbb58b3d3e931c258b11ef0405ab"),
            Hex.decode("8d95ddbc7ccc68982e5885b3ff0124cf22997231")});

        reseedValues.put("SHA-224/HMAC", new byte[][] {
            Hex.decode("dc23db9b7f9f20b47c5f66a20a3e814062761a85813d513fa68fffb6"),
            Hex.decode("da520ecafcbd13c1af9d6882a98c13e906b9497b4c6b0ce97f3cf6f4") });

        reseedValues.put("SHA-256/HMAC", new byte[][] {
            Hex.decode("d4f6183d6bc347533ce1d35bb15b0827516d13c7596f08be8640ede806f11558"),
            Hex.decode("035efd9db053cd09a42c5386c6cee390a24de11de7d0ab447bfaa89e4cf1ea5c") });

        reseedValues.put("SHA-384/HMAC", new byte[][] {
            Hex.decode("1b6b3e7460776ddb5a6cb339f3b8e4184543e53a9067a20317866ccf437eca98802058612fbd926770653221917e3208"),
            Hex.decode("dccd578a26ca50c2e65a5812e049f79fa90e5fa01ce2542a34bbe4fb35e2ef1955d1d48b823b69ff45e67e7757b75a98") });

        reseedValues.put("SHA-512/HMAC", new byte[][] {
            Hex.decode("394c512894673b146c3539f2ad708d49658fbb0cc305e06e2311267b0d97fc2daf76483d0b7824cf70b7dc035ee2cb206168f5616abc162976d970ba912cb45a"),
            Hex.decode("2269652d19f62a7da40a3a2e67cad2065209f26268fab3ff924fff91afef349a70bdb63599013936fbe98f1d7267cbc1ae6817264bfb8aead91c421b4a2f344f") });

        reseedValues.put("SHA-512(224)/HMAC", new byte[][] {
            Hex.decode("46a8083d5553f1372297d1915e848e0c94f508fd39fc3937dde0f719"),
            Hex.decode("6d61dd2447807e8a630468383f5b59393e8a0b2860f614198aa03f7a") });

        reseedValues.put("SHA-512(256)/HMAC", new byte[][] {
            Hex.decode("93c284295b6ba606037d63f8912ba22036f6e40c19d872935b71f944c323209e"),
            Hex.decode("e499e4e92dabcb0efd6d99cc5798f85cafc114f8fd9dc895b6212b92026fecc0") });

        reseedKats.put("SHA-1/HMAC", new byte[][]{
              Hex.decode("9d27edc5b266cdaeb53e1cbff2c7f45375a64bdb4c0494bf270ea0123f392dbfa7579ae28ca26b4e"),
              Hex.decode("ffbf224df85dbaa8bf456cf77d2119cb5e7f96d9a16f2193d7bf222be9c367ea7365d8d380ac8df8")});

        reseedKats.put("SHA-224/HMAC", new byte[][]{
            Hex.decode("78db8e7652435e8658ca8489939d503a717faeaf65a417ab56f152fe34f22adca2257ba7391c7b95"),
            Hex.decode("29124d827d159924f7c1a92558cd035c07efc26d244215a03cdbfcf83be2977ca52694f395de9792")});

        reseedKats.put("SHA-256/HMAC", new byte[][]{
            Hex.decode("2855b533c124d5acd070dcadfd9105d74aae4ceecfc0d848559e35b5860c10facb021ba31b216dbc"),
            Hex.decode("08d4e9daf7265a606af90c7b661468e96f097734de89f23bda6b6e4f3308c31714ca200d7b0ddd2e")});

        reseedKats.put("SHA-384/HMAC", new byte[][]{
            Hex.decode("a18f64766084ab908389dc1ed23485b67f6383278b436ccdf335a495572dc11c338e65bad9a09ec4"),
            Hex.decode("dacaf121aac01c68e8171a0926e974e2008ea5403230c133258ac1f99a349bdc185ad500983ee988")});

        reseedKats.put("SHA-512/HMAC", new byte[][]{
            Hex.decode("80530aa6df83038ee721f28da155be91780f5aefb3278d048102b9e1d18ad3ef8b9ced43da3e2b5c"),
            Hex.decode("104a35b8b289f49658521d2f408633fe677bea064ff7673d3d844d060239fd9f8db9681b11c42d8a")});

        reseedKats.put("SHA-512(224)/HMAC", new byte[][]{
            Hex.decode("046157b89fe2d0e98f0d403e8b7b6764c6c441c63dd6b1a4977a427810812e01733460e2d0eeeee5"),
            Hex.decode("ba49668623438e669d1a4764a33611467517d83ad266aa6be086fced53c8d5508c77ae6d34b7080d")});

        reseedKats.put("SHA-512(256)/HMAC", new byte[][]{
            Hex.decode("90965e6618c74e5ee1a7ee4b7e6d9b7d1dd791cb57d7f255a50ef6571731ad6e20e373e222bdc3f4"),
            Hex.decode("ec3fde0e481624700da0e355daa9b75585bc1d973a03e85ee3887afa6d40b9231c7f9ebe09bfe97c")});
    }

    private byte[] _K;
    private byte[] _V;
    private long   _reseedCounter;
    private EntropySource _entropySource;
    private Mac _hMac;
    private int _securityStrength;

    /**
     * Construct a SP800-90A Hash DRBG.
     * <p>
     * Minimum entropy requirement is the security strength requested.
     * </p>
     * @param hMac Hash MAC to base the DRBG on.
     * @param securityStrength security strength required (in bits)
     * @param entropySource source of entropy to use for seeding/reseeding.
     * @param personalizationString personalization string to distinguish this DRBG (may be null).
     * @param nonce nonce to further distinguish this DRBG (may be null).
     */
    public HMacSP800DRBG(Mac hMac, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        init(hMac, securityStrength, entropySource, personalizationString, nonce);
    }

    private void init(Mac hMac, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
    {
        if (securityStrength > DRBGUtils.getMaxSecurityStrength(hMac))
        {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        }

        if (entropySource.entropySize() < securityStrength)
        {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        }

        _securityStrength = securityStrength;
        _entropySource = entropySource;
        _hMac = hMac;
        _entropySource = entropySource;
        _K = new byte[hMac.getMacSize()];
        _V = new byte[_K.length];
        Arrays.fill(_V, (byte)1);

        byte[] entropy = getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalizationString);
        Arrays.fill(entropy, (byte)0);

        reseedFromSeedMaterial(seedMaterial);
    }

    private void hmac_DRBG_Update(byte[] seedMaterial)
    {
        hmac_DRBG_Update_Func(seedMaterial, (byte)0x00);
        if (seedMaterial != null)
        {
            hmac_DRBG_Update_Func(seedMaterial, (byte)0x01);
        }
    }

    private void hmac_DRBG_Update_Func(byte[] seedMaterial, byte vValue)
    {
        _hMac.init(new KeyParameterImpl(_K));

        _hMac.update(_V, 0, _V.length);
        _hMac.update(vValue);

        if (seedMaterial != null)
        {
            _hMac.update(seedMaterial, 0, seedMaterial.length);
        }

        _hMac.doFinal(_K, 0);

        _hMac.init(new KeyParameterImpl(_K));
        _hMac.update(_V, 0, _V.length);

        _hMac.doFinal(_V, 0);
    }

    /**
     * Return the block size (in bits) of the DRBG.
     *
     * @return the number of bits produced on each round of the DRBG.
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
        int numberOfBits = output.length * 8;

        if (numberOfBits > MAX_BITS_REQUEST)
        {
            throw new IllegalArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST);
        }

        if (predictionResistant)
        {
            reseed(additionalInput);
            additionalInput = null;
        }

        if (_reseedCounter > RESEED_MAX)
        {
            return -1;
        }

        // 2.
        if (additionalInput != null)
        {
            hmac_DRBG_Update(additionalInput);
        }

        // 3.
        byte[] rv = new byte[output.length];

        int m = output.length / _V.length;

        _hMac.init(new KeyParameterImpl(_K));

        for (int i = 0; i < m; i++)
        {
            _hMac.update(_V, 0, _V.length);
            _hMac.doFinal(_V, 0);

            System.arraycopy(_V, 0, rv, i * _V.length, _V.length);
        }

        if (m * _V.length < rv.length)
        {
            _hMac.update(_V, 0, _V.length);
            _hMac.doFinal(_V, 0);

            System.arraycopy(_V, 0, rv, m * _V.length, rv.length - (m * _V.length));
        }

        hmac_DRBG_Update(additionalInput);

        _reseedCounter++;

        System.arraycopy(rv, 0, output, 0, output.length);

        return numberOfBits;
    }

    /**
      * Reseed the DRBG.
      *
      * @param additionalInput additional input to be added to the DRBG in this step.
      */
    public void reseed(byte[] additionalInput)
    {
        byte[] entropy = getEntropy();
        byte[] seedMaterial = Arrays.concatenate(entropy, additionalInput);
        Arrays.fill(entropy, (byte)0);

        reseedFromSeedMaterial(seedMaterial);
    }

    private void reseedFromSeedMaterial(byte[] seedMaterial)
    {
        try
        {
            hmac_DRBG_Update(seedMaterial);
        }
        finally
        {
            Arrays.fill(seedMaterial, (byte)0);
        }

        _reseedCounter = 1;
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

        Arrays.fill(_K, (byte)0);
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
                byte[] origK = _K;
                byte[] origV = _V;
                long origReseedCounter = _reseedCounter;
                EntropySource origEntropySource = _entropySource;

                try
                {
                    byte[] personalization = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");
                    byte[] nonce = Hex.decode("2021222324");

                    final int entropyStrength = DRBGUtils.getMaxSecurityStrength(_hMac);

                    byte[][] expected = kats.get(algorithm.getName());

                    init(_hMac, _securityStrength, new DRBGUtils.KATEntropyProvider().get(entropyStrength), personalization, nonce);

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
                        init(_hMac, _securityStrength, new DRBGUtils.LyingEntropySource(entropyStrength), personalization, nonce);

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
                        init(_hMac, _securityStrength, new DRBGUtils.LyingEntropySource(20), personalization, nonce);

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
                        init(_hMac, entropyStrength + 1, new DRBGUtils.KATEntropyProvider().get(entropyStrength), personalization, nonce);

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
                    _K = origK;
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
                byte[] origK = _K;
                byte[] origV = _V;
                long origReseedCounter = _reseedCounter;
                EntropySource origEntropySource = _entropySource;

                try
                {
                    byte[] additionalInput = Hex.decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");

                    int entropyStrength = DRBGUtils.getMaxSecurityStrength(_hMac);
                    byte[][] expected = reseedKats.get(algorithm.getName());
                    byte[][] internalValues = reseedValues.get(algorithm.getName());

                    _K = Arrays.clone(internalValues[0]);
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
                    _K = origK;
                    _V = origV;
                    _reseedCounter = origReseedCounter;
                    _entropySource = origEntropySource;
                }
            }
        };
    }
}
