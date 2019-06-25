package org.bouncycastle.crypto.fips;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CipherOutputStream;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.OperatorUsingSecureRandom;
import org.bouncycastle.crypto.OutputEncryptor;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.general.FipsRegister;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.io.CipherInputStream;
import org.bouncycastle.crypto.internal.io.CipherOutputStreamImpl;
import org.bouncycastle.crypto.internal.macs.CMac;
import org.bouncycastle.crypto.internal.params.DesEdeParameters;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.crypto.internal.wrappers.SP80038FWrapEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for approved implementations of AES based algorithms
 */
public final class FipsTripleDES
{
    private FipsTripleDES()
    {

    }

    /**
     * Raw TripleDES algorithm, can be used for creating general purpose TripleDES keys.
     */
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("TripleDES");

    static final FipsEngineProvider<BlockCipher> ENGINE_PROVIDER;

    /**
     * TripleDES in electronic code book(ECB) mode.
     */
    public static final Parameters ECB = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB));

    /**
     * TripleDES in electronic code book mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters ECBwithPKCS7 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.PKCS7));

    /**
     * TripleDES in electronic code book mode with ISO10126-2 padding.
     */
    public static final Parameters ECBwithISO10126_2 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO10126_2));

    /**
     * TripleDES in electronic code book mode with X9.23 padding.
     */
    public static final Parameters ECBwithX923 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.X923));

    /**
     * TripleDES in electronic code book mode with ISO7816-4 padding.
     */
    public static final Parameters ECBwithISO7816_4 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.ISO7816_4));

    /**
     * TripleDES in electronic code book mode with trailing bit complement(TBC) padding.
     */
    public static final Parameters ECBwithTBC = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.ECB, Padding.TBC));

    /**
     * TripleDES in cipher block chaining(CBC) mode.
     */
    public static final Parameters CBC = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC));

    /**
     * TripleDES in cipher block chaining mode with PKCS#7/PKCS#5 padding.
     */
    public static final Parameters CBCwithPKCS7 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.PKCS7));

    /**
     * TripleDES in cipher block chaining mode with ISO10126-2 padding.
     */
    public static final Parameters CBCwithISO10126_2 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO10126_2));

    /**
     * TripleDES in cipher block chaining mode with X9.23 padding.
     */
    public static final Parameters CBCwithX923 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.X923));

    /**
     * TripleDES in cipher block chaining mode with ISO7816-4 padding.
     */
    public static final Parameters CBCwithISO7816_4 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.ISO7816_4));

    /**
     * TripleDES in cipher block chaining mode with trailing bit complement(TBC) padding.
     */
    public static final Parameters CBCwithTBC = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.TBC));

    /**
     * TripleDES in cipher block chaining mode cipher text stealing type 1.
     */
    public static final Parameters CBCwithCS1 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.CS1));

    /**
     * TripleDES in cipher block chaining mode cipher text stealing type 2.
     */
    public static final Parameters CBCwithCS2 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.CS2));

    /**
     * TripleDES in cipher block chaining mode cipher text stealing type 3.
     */
    public static final Parameters CBCwithCS3 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CBC, Padding.CS3));

    /**
     * TripleDES in cipher feedback(CFB) mode, 8 bit block size.
     */
    public static final Parameters CFB8 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CFB8));

    /**
     * TripleDES in output feedback(CFB) mode, 64 bit block size.
     */
    public static final Parameters CFB64 = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CFB64));

    /**
     * TripleDES in output feedback(OFB) mode, 64 bit blocksize.
     */
    public static final Parameters OFB = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.OFB64));

    /**
     * TripleDES in counter(CTR) mode.
     */
    public static final Parameters CTR = new Parameters(new FipsAlgorithm(ALGORITHM, Mode.CTR));

    /**
     * TripleDES as a FIPS SP800-38F/RFC 3394 key wrapper.
     */
    public static final WrapParameters TKW = new WrapParameters(new FipsAlgorithm(ALGORITHM, Mode.WRAP));

    /**
     * TripleDES CMAC.
     */
    public static final AuthParameters CMAC = new AuthParameters(new FipsAlgorithm(ALGORITHM, Mode.CMAC));

    static
    {
        EngineProvider provider = new EngineProvider();

        // FSM_STATE:3.TDES.0,"TDES ENCRYPT DECRYPT KAT", "The module is performing TDES encrypt and decrypt KAT self-test"
        // FSM_TRANS:3.TDES.0,"POWER ON SELF-TEST","TDES ENCRYPT DECRYPT KAT", "Invoke TDES Encrypt/Decrypt KAT self-test"
        provider.createEngine();
        // FSM_TRANS:3.TDES.1,"TDES ENCRYPT DECRYPT KAT", "POWER ON SELF-TEST", "TDES Encrypt/Decrypt KAT self-test successful completion"

        // FSM_STATE:3.TDES.1,"TDES-CMAC GENERATE VERIFY KAT", "The module is performing TDES-CMAC generate and verify KAT self-test"
        // FSM_TRANS:3.TDES.2, "POWER ON SELF-TEST", "TDES-CMAC GENERATE VERIFY KAT", "Invoke TDES CMAC Generate/Verify KAT self-test"
        cmacStartUpTest(provider);
        // FSM_TRANS:3.TDES.3, "TDES-CMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST", "TDES CMAC Generate/Verify KAT self-test successful completion"

        ENGINE_PROVIDER = provider;

        FipsRegister.registerEngineProvider(ALGORITHM, provider);
    }

    /**
     * General Triple-DES operator parameters.
     */
    public static final class Parameters
        extends FipsParameters
        implements ParametersWithIV
    {
        private final byte[] iv;

        Parameters(FipsAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        private Parameters(FipsAlgorithm algorithm, byte[] iv)
        {
            super(algorithm);

            ((Mode)algorithm.basicVariation()).checkIv(iv, 8);

            this.iv = iv;
        }

        public Parameters withIV(byte[] iv)
        {
            return new Parameters(this.getAlgorithm(), Arrays.clone(iv));
        }

        public Parameters withIV(SecureRandom random)
        {
            return new Parameters(this.getAlgorithm(), ((Mode)this.getAlgorithm().basicVariation()).createDefaultIvIfNecessary(8, random));
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }
    }

    /**
     * Parameters for Triple-DES AEAD and MAC modes..
     */
    public static final class AuthParameters
        extends FipsParameters
        implements AuthenticationParametersWithIV
    {
        private final byte[] iv;
        private final int macLenInBits;

        /**
         * Base constructor - the algorithm. In this case the tag length defaults to the 128 bits.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(FipsAlgorithm algorithm)
        {
            this(algorithm, null, Utils.getDefaultMacSize(algorithm, 64));  // tag full blocksize or half
        }

        /**
         * Base Constructor that takes an iv (nonce) and a tag length.
         *
         * @param algorithm    algorithm mode.
         * @param iv           iv, or nonce, to be used with this algorithm.
         * @param macLenInBits length of the checksum tag in bits.
         */
        private AuthParameters(FipsAlgorithm algorithm, byte[] iv, int macLenInBits)
        {
            super(algorithm);

            this.iv = iv;
            this.macLenInBits = macLenInBits;
        }

        public int getMACSizeInBits()
        {
            return macLenInBits;
        }

        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }

        public AuthParameters withIV(byte[] iv)
        {
            return new AuthParameters(this.getAlgorithm(), Arrays.clone(iv), this.macLenInBits);
        }

        public AuthParameters withIV(SecureRandom random)
        {
            return new AuthParameters(this.getAlgorithm(), this.getAlgorithm().createDefaultIvIfNecessary(8, random), this.macLenInBits);
        }

        /**
         * @param random source of randomness for iv (nonce)
         * @param ivLen  length of the iv (nonce) in bytes to use with the algorithm.
         */
        public AuthParameters withIV(SecureRandom random, int ivLen)
        {
            return new AuthParameters(this.getAlgorithm(), this.getAlgorithm().createIvIfNecessary(ivLen, random), this.macLenInBits);
        }

        public AuthParameters withMACSize(int macSizeInBits)
        {
            return new AuthParameters(this.getAlgorithm(), org.bouncycastle.util.Arrays.clone(iv), macSizeInBits);
        }
    }

    /**
     * Parameters for Triple-DES key wrap operators.
     */
    public static final class WrapParameters
       extends FipsParameters
   {
       private final boolean useInverse;

       WrapParameters(FipsAlgorithm algorithm)
       {
           this(algorithm, false);
       }

       private WrapParameters(FipsAlgorithm algorithm, boolean useInverse)
       {
           super(algorithm);

           this.useInverse = useInverse;
       }

       public boolean isUsingInverseFunction()
       {
           return useInverse;
       }

       public WrapParameters withUsingInverseFunction(boolean useInverse)
       {
           return new WrapParameters(getAlgorithm(), useInverse);
       }
   }

    /**
     * Triple-DES key generator.
     */
    public static final class KeyGenerator
        extends FipsSymmetricKeyGenerator
    {
        private final FipsAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        /**
         * Constructor to generate a general purpose Triple-DES key.
         *
         * @param keySizeInBits size of the key in bits.
         * @param random        secure random to use in key construction.
         */
        public KeyGenerator(int keySizeInBits, SecureRandom random)
        {
            this(ALGORITHM, keySizeInBits, random);
        }

        /**
         * Constructor to generate a specific purpose Triple-DES key for an algorithm in a particular parameter set.
         *
         * @param parameterSet  FIPS algorithm key is for,
         * @param keySizeInBits size of the key in bits.
         * @param random        secure random to use in key construction.
         */
        public KeyGenerator(FipsParameters parameterSet, int keySizeInBits, SecureRandom random)
        {
            this(parameterSet.getAlgorithm(), keySizeInBits, random);
        }

        private KeyGenerator(FipsAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateKeyGenRandom(random, 112, algorithm);

                if (keySizeInBits != 168 && keySizeInBits != 192)
                {
                    throw new IllegalArgumentException("Attempt to create key with unapproved key size [" + keySizeInBits + "]: " + algorithm.getName());
                }
            }
            else
            {
                if (keySizeInBits != 112 && keySizeInBits != 168 && keySizeInBits != 128 && keySizeInBits != 192)
                {
                    throw new IllegalArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.getName());
                }
            }

            this.algorithm = algorithm;
            this.keySizeInBits = keySizeInBits;
            this.random = random;
        }

        public SymmetricKey generateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new DesEdeKeyGenerator(algorithm);

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for basic Triple-DES encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends FipsSymmetricOperatorFactory<Parameters>
    {
        @Override
        public FipsOutputEncryptor<Parameters> createOutputEncryptor(final SymmetricKey key, final Parameters parameters)
        {
            final ValidatedSymmetricKey sKey = validateKey(key, parameters, false);

            return new OutEncryptor(sKey, parameters, null);
        }

        @Override
        public FipsOutputDecryptor<Parameters> createOutputDecryptor(final SymmetricKey key, final Parameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters, true);

            final BufferedBlockCipher cipher = BlockCipherUtils.createStandardCipher(false, sKey, ENGINE_PROVIDER, parameters, null);

            return new FipsOutputDecryptor<Parameters>()
            {
                @Override
                public Parameters getParameters()
                {
                    return parameters;
                }

                public int getMaxOutputSize(int inputLen)
                {
                    return cipher.getOutputSize(inputLen);
                }

                public int getUpdateOutputSize(int inputLen)
                {
                    return cipher.getUpdateOutputSize(inputLen);
                }

                @Override
                public CipherOutputStream getDecryptingStream(OutputStream out)
                {
                    if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                    {
                        return new CipherOutputStreamImpl(out, (StreamCipher)cipher.getUnderlyingCipher());
                    }

                    return new CipherOutputStreamImpl(out, cipher);
                }
            };
        }

        @Override
        public FipsInputDecryptor<Parameters> createInputDecryptor(final SymmetricKey key, final Parameters parameters)
        {
            final ValidatedSymmetricKey sKey = validateKey(key, parameters, true);
            final BufferedBlockCipher cipher = BlockCipherUtils.createStandardCipher(false, sKey, ENGINE_PROVIDER, parameters, null);

            return new FipsInputDecryptor<Parameters>()
            {
                @Override
                public Parameters getParameters()
                {
                    return parameters;
                }

                @Override
                public InputStream getDecryptingStream(InputStream in)
                {
                    if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                    {
                        return new CipherInputStream(in, (StreamCipher)cipher.getUnderlyingCipher());
                    }

                    return new CipherInputStream(in, cipher);
                }
            };
        }

        private class OutEncryptor
            extends FipsOutputEncryptor<Parameters>
            implements OperatorUsingSecureRandom<OutputEncryptor<Parameters>>
        {
            private final Parameters parameters;
            private final ValidatedSymmetricKey key;
            private final BufferedBlockCipher cipher;

            public OutEncryptor(ValidatedSymmetricKey key, Parameters parameters, SecureRandom random)
            {
                this.key = key;
                this.parameters = parameters;

                cipher = BlockCipherUtils.createStandardCipher(true, key, ENGINE_PROVIDER, parameters, random);
            }

            public CipherOutputStream getEncryptingStream(OutputStream out)
            {
                if (cipher.getUnderlyingCipher() instanceof StreamCipher)
                {
                    return new CipherOutputStreamImpl(out, (StreamCipher)cipher.getUnderlyingCipher());
                }

                return new CipherOutputStreamImpl(out, cipher);
            }

            public OutputEncryptor<Parameters> withSecureRandom(SecureRandom random)
            {
                return new OutEncryptor(key, parameters, random);
            }

            public Parameters getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return cipher.getOutputSize(inputLen);
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return cipher.getUpdateOutputSize(inputLen);
            }
        }
    }

    /**
     * Factory for producing FIPS Triple-DES MAC calculators.
     */
    public static final class MACOperatorFactory
        extends FipsMACOperatorFactory<AuthParameters>
    {
        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return makeMAC(parameters).getMacSize();
        }

        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            final Mac mac = makeMAC(parameters);
            ValidatedSymmetricKey sKey = validateKey(key, parameters, false);

            if(parameters.getIV() != null)
            {
                mac.init(Utils.getParametersWithIV(sKey, parameters.getIV()));
            }
            else
            {
                mac.init(Utils.getKeyParameter(sKey));
            }

            return mac;
        }
    }

    static FipsEngineProvider<Mac> getMacProvider(final FipsAlgorithm algorithm)
    {
        final FipsEngineProvider<Mac> macProvider;

        switch (((Mode)algorithm.basicVariation()))
        {
        case CMAC:
            macProvider = new FipsEngineProvider<Mac>()
            {
                public Mac createEngine()
                {
                    return new CMac(ENGINE_PROVIDER.createEngine());
                }
            };
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsTripleDES MAC Provider: " + algorithm);
        }

        return macProvider;
    }

    static Mac makeMAC(final AuthParameters authParameters)
    {
        final Mac mac;

        switch (((Mode)authParameters.getAlgorithm().basicVariation()))
        {
        case CMAC:
            mac = new CMac(ENGINE_PROVIDER.createEngine(), authParameters.macLenInBits);
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsTripleDES.OperatorFactory.createMACCalculator: " + authParameters.getAlgorithm());
        }

        return mac;
    }

    /**
     * Factory for producing FIPS Triple-DES key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends FipsKeyWrapOperatorFactory<WrapParameters, SymmetricKey>
    {
        private Wrapper createWrapper(FipsAlgorithm algorithm, boolean useInverse)
        {
            Wrapper  cipher;

            switch(((Mode)algorithm.basicVariation()))
            {
            case WRAP:
                cipher = new SP80038FWrapEngine(ENGINE_PROVIDER.createEngine(), useInverse);
                break;
            default:
                throw new IllegalArgumentException("Unknown algorithm passed to FipsDESEDE.KeyWrapOperatorFactory: " + algorithm.getName());
            }

            return cipher;
        }

        @Override
        public FipsKeyWrapper<WrapParameters> createKeyWrapper(SymmetricKey key, final WrapParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters, false);
            final Wrapper wrapper = createWrapper(parameters.getAlgorithm(), parameters.useInverse);

            wrapper.init(true, new KeyParameterImpl(sKey.getKeyBytes()));

            return new FipsKeyWrapper<WrapParameters>()
            {
                public WrapParameters getParameters()
                {
                    return parameters;
                }

                public byte[] wrap(byte[] in, int inOff, int inLen)
                    throws PlainInputProcessingException
                {
                    try
                    {
                        return wrapper.wrap(in, inOff, inLen);
                    }
                    catch (Exception e)
                    {
                        throw new PlainInputProcessingException("Unable to wrap key: " + e.getMessage(), e);
                    }
                }
            };
        }

        @Override
        public FipsKeyUnwrapper<WrapParameters> createKeyUnwrapper(SymmetricKey key, final WrapParameters parameters)
        {
            ValidatedSymmetricKey sKey = validateKey(key, parameters, true);

            final Wrapper wrapper = createWrapper(parameters.getAlgorithm(), parameters.useInverse);

            wrapper.init(false, new KeyParameterImpl(sKey.getKeyBytes()));

            return new FipsKeyUnwrapper<WrapParameters>()
            {
                public WrapParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] unwrap(byte[] in, int inOff, int inLen)
                    throws InvalidWrappingException
                {
                    try
                    {
                        return wrapper.unwrap(in, inOff, inLen);
                    }
                    catch (InvalidCipherTextException e)
                    {
                        throw new InvalidWrappingException("Unable to unwrap key: " + e.getMessage(), e);
                    }
                }
            };
        }
    }

    private static void validateKeySize(Algorithm algorithm, int keySize)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            if (keySize != 168 && keySize != 192)
            {
                // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                throw new IllegalKeyException("Key must be of length 192 bits: " + algorithm.getName());
            }
        }
        else
        {
            if (keySize != 112 && keySize != 168 && keySize != 128 && keySize != 192)
            {
                throw new IllegalKeyException("Key must be of length 128 or 192 bits: " + algorithm.getName());
            }
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, org.bouncycastle.crypto.Parameters parameters, boolean forReading)
    {
        // FSM_STATE:5.13,"TDES KEY VALIDITY TEST", "The module is validating the size and purpose of an TDES key"
        // FSM_TRANS:5.TDES.0,"CONDITIONAL TEST", "TDES KEY VALIDITY TEST", "Invoke Validity test on TDES key"
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (!(forReading && keyLength == 128))      // decryption using 2 key TDES okay,
        {
            validateKeySize(key.getAlgorithm(), keyLength);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (!forReading && !DesEdeParameters.isReal3Key(vKey.getKeyBytes()))
                {
                    // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                    throw new IllegalKeyException("Key not real 3-Key DESEDE key");
                }
            }
        }

        if (!Properties.isOverrideSet("org.bouncycastle.tripledes.allow_weak"))
        {
            if (!forReading)
            {
                if (DesEdeParameters.isActuallyDesKey(vKey.getKeyBytes()))
                {
                    // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                    throw new IllegalKeyException("Attempt to use repeated DES key: " + key.getAlgorithm().getName());
                }
                if (DesEdeParameters.isWeakKey(vKey.getKeyBytes(), 0, vKey.getKeyBytes().length))
                {
                    // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                    throw new IllegalKeyException("Attempt to use weak key: " + key.getAlgorithm().getName());
                }
            }
        }

        Algorithm algorithm = key.getAlgorithm();

        if (!algorithm.equals(ALGORITHM))
        {
            if (!algorithm.equals(parameters.getAlgorithm()))
            {
                // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                throw new IllegalKeyException("FIPS Key not for specified algorithm");
            }
        }

        // FSM_TRANS:5.TDES.0,"TDES KEY VALIDITY TEST", "CONDITIONAL TEST", "Validity test on TDES key successful"
        return vKey;
    }

    private static final class EngineProvider
        extends FipsEngineProvider<BlockCipher>
    {
        public BlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new DesEdeEngine(), new VariantKatTest<DesEdeEngine>()
            {
                public void evaluate(DesEdeEngine tripleDesEngine)
                {
                    byte[] input = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
                    byte[] output = Hex.decode("f7cfbe5e6c38b35a62815c962fcaf7a863af5450ec85fdab");
                    byte[] tmp = new byte[input.length];

                    KeyParameter key = new KeyParameterImpl(Hex.decode("0102020404070708080b0b0d0d0e0e101013131515161619"));

                    tripleDesEngine.init(true, key);

                    tripleDesEngine.processBlock(input, 0, tmp, 0);
                    tripleDesEngine.processBlock(input, 8, tmp, 8);
                    tripleDesEngine.processBlock(input, 16, tmp, 16);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    tripleDesEngine.init(false, key);

                    tripleDesEngine.processBlock(tmp, 0, tmp, 0);
                    tripleDesEngine.processBlock(tmp, 8, tmp, 8);
                    tripleDesEngine.processBlock(tmp, 16, tmp, 16);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }

    private static void cmacStartUpTest(EngineProvider provider)
    {
        SelfTestExecutor.validate(ALGORITHM, provider, new BasicKatTest<EngineProvider>()
        {
            public boolean hasTestPassed(EngineProvider provider)
                throws Exception
            {
                byte[] input16 = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
                byte[] output_k128_m16 = Hex.decode("c0b9bbee139722ab");

                Mac mac = new CMac(provider.createEngine(), 64);

                //128 bytes key

                KeyParameter key = new KeyParameterImpl(Hex.decode("0102020404070708080b0b0d0d0e0e101013131515161619"));

                // 0 bytes message - 128 bytes key
                mac.init(key);

                mac.update(input16, 0, input16.length);

                byte[] out = new byte[8];

                mac.doFinal(out, 0);

                return Arrays.areEqual(out, output_k128_m16);
            }
        });
    }
}
