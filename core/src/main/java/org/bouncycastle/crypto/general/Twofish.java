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
 * Source class for implementations of Twofish based algorithms.
 */
public final class Twofish
{
    private Twofish()
    {

    }

    /**
     * Raw Twofish algorithm, can be used for creating general purpose Twofish keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("Twofish");

    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    /**
     * Twofish in electronic code book (ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * Twofish in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * Twofish in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * Twofish in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * Twofish in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * Twofish in electronic code book mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * Twofish in cipher block chaining (CBC) mode.
     */
    public static final Parameters CBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * Twofish in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters CBCwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * Twofish in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final Parameters CBCwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * Twofish in cipher block chaining mode with X9.23 padding.
     */
    public static final Parameters CBCwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * Twofish in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final Parameters CBCwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * Twofish in cipher block chaining mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters CBCwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * Twofish in cipher block chaining mode cipher text stealing type 1.
     */
    public static final Parameters CBCwithCS1 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * Twofish in cipher block chaining mode cipher text stealing type 2.
     */
    public static final Parameters CBCwithCS2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * Twofish in cipher block chaining mode cipher text stealing type 3.
     */
    public static final Parameters CBCwithCS3 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * Twofish in cipher feedback (CFB) mode, 8 bit block size.
     */
    public static final Parameters CFB8 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * Twofish in cipher feedback (CFB) mode, 128 bit block size.
     */
    public static final Parameters CFB128 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB128));

    /**
     * Twofish in output feedback (OFB) mode.
     */
    public static final Parameters OFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OFB128));

    /**
     * Twofish in counter (CTR) mode.
     */
    public static final Parameters CTR = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * Twofish in Galois/Counter Mode (GCM).
     */
    public static final AuthParameters GCM = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.GCM));

    /**
     * Twofish in counter with CBC-MAC (CCM).
     */
    public static final AuthParameters CCM = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CCM));

    /**
     * Twofish in offset code book (OCB) mode.
     */
    public static final AuthParameters OCB = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.OCB));

    /**
     * Twofish in EAX mode.
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.EAX));

    /**
     * Twofish in OpenPGP cipher feedback (CFB) mode.
     */
    public static final Parameters OpenPGPCFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OpenPGPCFB));

    /**
     * Twofish cipher-based MAC algorithm.
     */
    public static final AuthParameters CMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CMAC));

    /**
     * Twofish cipher-based GMAC algorithm.
     */
    public static final AuthParameters GMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.GMAC));

    /**
     * Twofish as a FIPS/RFC 3394 key wrapper.
     */
    public static final WrapParameters KW = new WrapParameters(new GeneralAlgorithm(ALGORITHM, Mode.WRAP));

    /**
     * Twofish as a FIPS/RFC 3394 key wrapper with padding.
     */
    public static final WrapParameters KWP = new WrapParameters(new GeneralAlgorithm(ALGORITHM, Mode.WRAPPAD));

    /**
     * Parameters for general Twofish block cipher modes.
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
     * Parameters for Twofish AEAD and MAC modes.
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
     * General WRAP operator parameters for KW and KWP.
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
     * Twofish key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(int keySizeInBits, SecureRandom random)
        {
            this(ALGORITHM, keySizeInBits, random);
        }

        public KeyGenerator(GeneralParameters parameterSet, int keySizeInBits, SecureRandom random)
        {
             this((GeneralAlgorithm)parameterSet.getAlgorithm(), keySizeInBits, random);
        }

        private KeyGenerator(GeneralAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            this.algorithm = algorithm;

            if (invalidKeySize(keySizeInBits))
            {
                throw new IllegalArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.getName());
            }

            this.keySizeInBits = keySizeInBits;
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
     * Factory for basic Twofish encryption/decryption operators.
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
     * Factory for Twofish AEAD encryption/decryption operators.
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
     * Factory for producing Twofish MAC calculators.
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
     * Factory for Twofish key wrap/unwrap operators.
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

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("Twofish key must be of length 64-256 bits");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, paramAlgorithm);

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength < 64 || keyLength > 256;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<BlockCipher>
    {
        public BlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new TwofishEngine(), new VariantKatTest<TwofishEngine>()
            {
                public void evaluate(TwofishEngine engine)
                {
                    byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
                    byte[] output = Hex.decode("b7b5fb57ec446a11cbb7e6292342537b");
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
