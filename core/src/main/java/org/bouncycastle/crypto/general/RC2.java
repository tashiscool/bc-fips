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
 * Source class for implementations of RC2 based algorithms.
 */
public final class RC2
{
    private RC2()
    {

    }

    /**
     * Raw RC2 algorithm, can be used for creating general purpose RC2 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("RC2");
    
    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    /**
     * RC2 in electronic code book (ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * RC2 in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * RC2 in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * RC2 in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * RC2 in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * RC2 in electronic code book mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * RC2 in cipher block chaining (CBC) mode.
     */
    public static final Parameters CBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * RC2 in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters CBCwithPKCS7 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * RC2 in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final Parameters CBCwithISO10126_2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * RC2 in cipher block chaining mode with X9.23 padding.
     */
    public static final Parameters CBCwithX923 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * RC2 in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final Parameters CBCwithISO7816_4 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * RC2 in cipher block chaining mode with trailing bit complement (TBC) padding.
     */
    public static final Parameters CBCwithTBC = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * RC2 in cipher block chaining mode cipher text stealing type 1.
     */
    public static final Parameters CBCwithCS1 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * RC2 in cipher block chaining mode cipher text stealing type 2.
     */
    public static final Parameters CBCwithCS2 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * RC2 in cipher block chaining mode cipher text stealing type 3.
     */
    public static final Parameters CBCwithCS3 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * RC2 in cipher feedback (CFB) mode, 8 bit block size.
     */
    public static final Parameters CFB8 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * RC2 in cipher feedback (CFB) mode, 64 bit block size.
     */
    public static final Parameters CFB64 = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB64));

    /**
     * RC2 in output feedback (OFB) mode, 64 bit block size.
     */
    public static final Parameters OFB = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.OFB64));

    /**
     * RC2 in counter (CTR) mode.
     */
    public static final Parameters CTR = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * RC2 in EAX mode.
     */
    public static final AuthParameters EAX = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.EAX));

    /**
     * RC2 cipher-based CBC MAC algorithm.
     */
    public static final AuthParameters CBC_MAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CBCMAC));

    /**
     * RC2  CFB8MAC.
     */
    public static final AuthParameters CFB8_MAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CFB8MAC));

    /**
     * RC2 cipher-based MAC algorithm.
     */
    public static final AuthParameters CMAC = new AuthParameters(new GeneralAlgorithm(ALGORITHM, Mode.CMAC));

    /**
     * RC2 RFC 3217 key wrapper.
     */
    public static final Parameters RFC3217_WRAP = new Parameters(new GeneralAlgorithm(ALGORITHM, Mode.RFC3217_WRAP));

    /**
     * Parameters for general RC2 block cipher modes.
     */
    public static final class Parameters
        extends GeneralParameters<GeneralAlgorithm>
        implements ParametersWithIV
    {
        private final byte[] iv;
        private final int    effectiveKeySizeInBits;

        Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, -1, null);
        }

        private Parameters(GeneralAlgorithm algorithm, int effectiveKeySizeInBits, byte[] iv)
        {
            super(algorithm);
            this.effectiveKeySizeInBits = effectiveKeySizeInBits;
            this.iv = iv;
        }

        public Parameters withEffectiveKeySizeInBits(int effectiveKeySizeInBits)
        {
            return new Parameters(this.getAlgorithm(), effectiveKeySizeInBits, this.iv);
        }

        public Parameters withIV(byte[] iv)
        {
            return new Parameters(this.getAlgorithm(), this.getEffectiveKeySizeInBits(), Arrays.clone(iv));
        }

        public Parameters withIV(SecureRandom random)
        {
            return new Parameters(this.getAlgorithm(), this.getEffectiveKeySizeInBits(), this.getAlgorithm().createDefaultIvIfNecessary(8, random));
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }

        public int getEffectiveKeySizeInBits()
        {
            return effectiveKeySizeInBits;
        }
    }

    /**
     * Parameters for RC2 AEAD and MAC modes.
     */
    public static final class AuthParameters
        extends GeneralAuthParameters<AuthParameters>
    {
        private final int effectiveKeySizeInBits;

        private AuthParameters(GeneralAlgorithm algorithm, int effectiveKeySizeInBits, byte[] iv, int tagLenInBits)
        {
            super(algorithm, 8, iv, tagLenInBits);
            this.effectiveKeySizeInBits = effectiveKeySizeInBits;
        }

        /**
         * Base constructor - the algorithm, null IV.
         * In this case the tag length defaults to the 64 for CMAC, 32 bits otherwise.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, -1, null, Utils.getDefaultMacSize(algorithm, 64));  // tag full blocksize or half
        }

        public AuthParameters withEffectiveKeySizeInBits(int effectiveKeySizeInBits)
        {
            return new AuthParameters(this.getAlgorithm(), effectiveKeySizeInBits, this.iv, this.macLenInBits);
        }

        protected AuthParameters create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits)
        {
            return new AuthParameters(algorithm, effectiveKeySizeInBits, iv, macSizeInBits);
        }

        public int getEffectiveKeySizeInBits()
                {
                    return effectiveKeySizeInBits;
                }
    }

    /**
     * RC2 key generator.
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
     * Factory for basic RC2 encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricOperatorFactory<Parameters>
    {
        @Override
        protected BufferedBlockCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            KeyParameter keyParameter = createRC2Parameters(key, parameters.getAlgorithm(), parameters.getEffectiveKeySizeInBits());
            
            return CipherUtils.createStandardCipher(forEncryption, keyParameter, ENGINE_PROVIDER, parameters, random);
        }
    }

    /**
     * Factory for RC2 AEAD encryption/decryption operators.
     */
    public static final class AEADOperatorFactory
        extends GuardedAEADOperatorFactory<AuthParameters>
    {
        @Override
        protected AEADBlockCipher createAEADCipher(boolean forEncryption, SymmetricKey key, AuthParameters parameters)
        {
            KeyParameter keyParameter = createRC2Parameters(key, parameters.getAlgorithm(), parameters.getEffectiveKeySizeInBits());

            return CipherUtils.createStandardAEADCipher(forEncryption, keyParameter, ENGINE_PROVIDER, parameters);
        }
    }

    /**
     * Factory for producing RC2 MAC calculators.
     */
    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            KeyParameter keyParameter = createRC2Parameters(key, parameters.getAlgorithm(), parameters.getEffectiveKeySizeInBits());

            return CipherUtils.createStandardMac(keyParameter, ENGINE_PROVIDER, parameters);
        }

        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return Utils.bitsToBytes(parameters.macLenInBits);
        }
    }

    /**
     * Factory for RC2 key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends GuardedKeyWrapOperatorFactory<Parameters, SymmetricKey>
    {
        protected Wrapper createWrapper(boolean forWrapping, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            KeyParameter keyParameter = createRC2Parameters(key, parameters.getAlgorithm(), parameters.getEffectiveKeySizeInBits());

            return CipherUtils.createStandardWrapper(forWrapping, keyParameter, ENGINE_PROVIDER, parameters, false, random);
        }
    }

    private static KeyParameter createRC2Parameters(SymmetricKey key, Algorithm algorithm, int effKeySizeInBits)
    {
        ValidatedSymmetricKey sKey = validateKey(key, algorithm);

        KeyParameter keyParameter;
        if (effKeySizeInBits > 0)
        {
            keyParameter = new RC2Parameters(sKey.getKeyBytes(), effKeySizeInBits);
        }
        else
        {
            keyParameter = new KeyParameterImpl(sKey.getKeyBytes());
        }

        return keyParameter;
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm paramAlgorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("Key the wrong size for RC2");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, paramAlgorithm);

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength < 8 || keyLength > 1024;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<BlockCipher>
    {
        public BlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new RC2Engine(), new VariantKatTest<RC2Engine>()
            {
                public void evaluate(RC2Engine engine)
                {
                    byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
                    byte[] output = Hex.decode("c9ac8a939b3868f6fcc81336913d515e");
                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(Hex.decode("101112131415161718191a1b1c1d1e1f"));

                    engine.init(true, key);

                    engine.processBlock(input, 0, tmp, 0);
                    engine.processBlock(input, 8, tmp, 8);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    engine.init(false, key);

                    engine.processBlock(tmp, 0, tmp, 0);
                    engine.processBlock(tmp, 8, tmp, 8);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }
}
