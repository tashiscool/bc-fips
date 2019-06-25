package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * The SEED encryption algorithm as described in RFC 4269.
 */
public final class SEED
{
    private SEED()
    {

    }

    /**
     * Raw SEED algorithm, can be used for creating general purpose SEED keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("SEED");

    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    /**
     * SEED in electronic code book (ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * SEED in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * SEED in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * SEED in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * SEED in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * SEED in electronic code book mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * SEED in cipher block chaining (CBC) mode.
     */
    public static final Parameters CBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * SEED in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters CBCwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * SEED in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final Parameters CBCwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * SEED in cipher block chaining mode with X9.23 padding.
     */
    public static final Parameters CBCwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * SEED in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final Parameters CBCwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * SEED in cipher block chaining mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters CBCwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * SEED in cipher block chaining mode cipher text stealing type 1.
     */
    public static final Parameters CBCwithCS1 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * SEED in cipher block chaining mode cipher text stealing type 2.
     */
    public static final Parameters CBCwithCS2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * SEED in cipher block chaining mode cipher text stealing type 3.
     */
    public static final Parameters CBCwithCS3 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * SEED in cipher feedback (CFB) mode.
     */
    public static final Parameters CFB128 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB128));

    /**
     * SEED in cipher feedback (CFB) mode, 8 bit block size.
     */
    public static final Parameters CFB8 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * SEED in output feedback (OFB) mode.
     */
    public static final Parameters OFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OFB128));

    /**
     * SEED in counter (CTR) mode.
     */
    public static final Parameters CTR = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * SEED in Galois/Counter Mode (GCM).
     */
    public static final AuthParameters GCM = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.GCM));

    /**
     * SEED in counter with CBC-MAC (CCM).
     */
    public static final AuthParameters CCM = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CCM));

    /**
     * SEED in offset code book (OCB) mode.
     */
    public static final AuthParameters OCB = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.OCB));

    /**
     * SEED in EAX mode.
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.EAX));

    /**
     * SEED cipher-based MAC algorithm.
     */
    public static final AuthParameters CMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CMAC));

    /**
     * SEED cipher-based GMAC algorithm.
     */
    public static final AuthParameters GMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.GMAC));

    /**
     * SEED as a FIPS/RFC 4010 key wrapper.
     */
    public static final WrapParameters KW = new WrapParameters(new GeneralAlgorithm(ALGORITHM, Mode.WRAP));

    /**
     * SEED as a FIPS/RFC 4010 key wrapper.
     */
    public static final WrapParameters KWP = new WrapParameters(new GeneralAlgorithm(ALGORITHM, Mode.WRAPPAD));

    /**
     * Parameters for general SEED block cipher modes.
     */
    public static final class Parameters
        extends GeneralParametersWithIV<Parameters>
    {
        private Parameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm, 16, algorithm.checkIv(iv, 16));
        }

        Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        protected Parameters create(GeneralAlgorithm algorithm, byte[] iv)
        {
            return new Parameters(algorithm, iv);
        }
    }

    /**
     * Parameters for SEED AEAD and MAC modes.
     */
    public static final class AuthParameters
        extends GeneralAuthParameters<AuthParameters>
    {
        private AuthParameters(GeneralAlgorithm algorithm, byte[] iv, int macLenInBits)
        {
            super(algorithm, 16, iv, macLenInBits);
        }

        /**
         * Base constructor - the algorithm, null IV.
         * In this case the tag length defaults to the 128 for GCM, CMAC, or GMAC, 64 bits otherwise.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null, Utils.getDefaultMacSize(algorithm, 128));  // tag full blocksize or half
        }

        protected AuthParameters create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits)
        {
            return new AuthParameters(algorithm, iv, macSizeInBits);
        }
    }

    /**
     * SEED general WRAP operator parameters for KW and KWP.
     */
    public static final class WrapParameters
        extends GeneralParameters<GeneralAlgorithm>
        implements ParametersWithIV
    {
        private final byte[] iv;
        private final boolean useInverse;

        WrapParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null, false);
        }

        private WrapParameters(GeneralAlgorithm algorithm, byte[] iv, boolean useInverse)
        {
            super(algorithm);

            if (iv != null)
            {
                ((Mode)algorithm.basicVariation()).checkIv(iv, getIvLength());
            }

            this.iv = iv;
            this.useInverse = useInverse;
        }

        public WrapParameters withUsingInverseFunction(boolean useInverse)
        {
            return new WrapParameters(getAlgorithm(), Arrays.clone(iv), useInverse);
        }

        public WrapParameters withIV(byte[] iv)
        {
            return new WrapParameters(this.getAlgorithm(), Arrays.clone(iv), this.useInverse);
        }

        public WrapParameters withIV(SecureRandom random)
        {
            return new WrapParameters(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(getIvLength(), random), this.useInverse);
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }

        public boolean isUsingInverseFunction()
        {
            return useInverse;
        }

        private int getIvLength()
        {
            return getAlgorithm().equals(KW.getAlgorithm()) ? 8 : 4;
        }
    }

    /**
     * SEED key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(SecureRandom random)
        {
            this(ALGORITHM, random);
        }

        public KeyGenerator(GeneralParameters parameterSet, SecureRandom random)
        {
             this((GeneralAlgorithm)parameterSet.getAlgorithm(), random);
        }

        private KeyGenerator(GeneralAlgorithm algorithm, SecureRandom random)
        {
            this.algorithm = algorithm;
            this.keySizeInBits = 128;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for basic SEED encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricOperatorFactory<Parameters>
    {
        @Override
        protected BufferedBlockCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters, random);
        }
    }

    /**
     * Factory for SEED AEAD encryption/decryption operators.
     */
    public static final class AEADOperatorFactory
        extends GuardedAEADOperatorFactory<AuthParameters>
    {
        @Override
        protected AEADBlockCipher createAEADCipher(boolean forEncryption, SymmetricKey key, AuthParameters parameters)
        {
            return CipherUtils.createStandardAEADCipher(forEncryption, validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters);
        }
    }

    /**
     * Factory for producing SEED MAC calculators.
     */
    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            return CipherUtils.createStandardMac(validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters);
        }

        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return Utils.bitsToBytes(parameters.macLenInBits);
        }
    }

    /**
     * Factory for SEED key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends GuardedKeyWrapOperatorFactory<WrapParameters, SymmetricKey>
    {
        protected Wrapper createWrapper(boolean forWrapping, SymmetricKey key, WrapParameters parameters, SecureRandom random)
        {
            return CipherUtils.createStandardWrapper(forWrapping, validateKey(key, parameters.getAlgorithm()), ENGINE_PROVIDER, parameters, parameters.useInverse, random);
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm paramAlgorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        if (invalidKeySize(vKey))
        {
            throw new IllegalKeyException("SEED key must be of length 128");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, paramAlgorithm);

        return vKey;
    }

    private static boolean invalidKeySize(ValidatedSymmetricKey vKey)
    {
        return vKey.getKeySizeInBits() != 128;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<BlockCipher>
    {
        public BlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new SEEDEngine(), new VariantKatTest<SEEDEngine>()
            {
                public void evaluate(SEEDEngine engine)
                {
                    byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
                    byte[] output = Hex.decode("af527210eb79c7a023abf348e70c9045");
                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

                    engine.init(true, key);

                    engine.processBlock(input, 0, tmp, 0);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    engine.init(false, key);

                    engine.processBlock(tmp, 0, tmp, 0);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }
}
