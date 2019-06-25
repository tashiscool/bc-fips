package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.asymmetric.DSAValidationParameters;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.EngineProvider;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.crypto.internal.PrimeCertaintyCalculator;
import org.bouncycastle.crypto.internal.params.DsaKeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaParameterGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaParameters;
import org.bouncycastle.crypto.internal.params.DsaPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaValidationParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.math.internal.Primes;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Source class for FIPS approved implementations of DSA based algorithms.
 */
public final class FipsDSA
{
    /**
     * DSA key marker, can be used for creating general purpose DSA keys.
     */
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("DSA", null);

    /**
     * DSA algorithm parameter source - default is SHA-1
     */
    public static final Parameters DSA = new Parameters();

    private static final EngineProvider<DsaSigner> ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new DsaProvider();

        // FSM_STATE:3.DSA.0,"POWER ON SELF-TEST", "DSA SIGN VERIFY KAT", "The module is performing ECDSA sign and verify KAT self-test"
        // FSM_TRANS:3.DSA.0,"POWER ON SELF-TEST", "DSA SIGN VERIFY KAT", "Invoke DSA Sign/Verify KAT self-test"
        provider.createEngine();
        // FSM_TRANS:3.DSA.1,"DSA SIGN VERIFY KAT", "POWER ON SELF-TEST", "DSA Sign/Verify KAT self-test successful completion"

        ENGINE_PROVIDER = provider;
    }

    private FipsDSA()
    {

    }

    private static DsaParameters getDomainParams(DSADomainParameters dsaParams)
    {
        return new DsaParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
    }

    private static DsaPrivateKeyParameters getLwKey(final AsymmetricDSAPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<DsaPrivateKeyParameters>()
        {
            public DsaPrivateKeyParameters run()
            {
                return new DsaPrivateKeyParameters(privKey.getX(), getDomainParams(privKey.getDomainParameters()));
            }
        });
    }

    private static void validateKeyPair(AsymmetricCipherKeyPair kp)
    {
        SelfTestExecutor.validate(ALGORITHM, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
        {
            public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
            {
                final byte[] data = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                DsaSigner signer = new DsaSigner();

                signer.init(true, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                BigInteger[] rv = signer.generateSignature(data);

                signer.init(false, kp.getPublic());

                return signer.verifySignature(data, rv[0], rv[1]);
            }
        });
    }

    /**
     * Parameters for DSA key pair generation.
     */
    public static final class KeyGenParameters
         extends FipsParameters
    {
        private final DSADomainParameters domainParameters;

        /**
         * Base constructor for the default algorithm ID.
         *
         * @param domainParameters DSA domain parameters representing the parameter set any generated keys will be for.
         */
        public KeyGenParameters(DSADomainParameters domainParameters)
        {
            super(ALGORITHM);
            this.domainParameters = domainParameters;
        }

        /**
         * Return the DSA domain parameters for this object.
         *
         * @return the DSA domain parameter set.
         */
        public DSADomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * Parameters for DSA signatures.
     */
    public static final class Parameters
        extends FipsParameters
    {
        private final FipsDigestAlgorithm digestAlgorithm;

        Parameters()
        {
            super(FipsDSA.ALGORITHM);
            this.digestAlgorithm = FipsSHS.Algorithm.SHA1;
        }

        private Parameters(FipsDigestAlgorithm digestAlgorithm)
        {
            super(FipsDSA.ALGORITHM);

            if (digestAlgorithm == null && CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                PrivilegedUtils.checkPermission(Permissions.TlsNullDigestEnabled);
            }

            this.digestAlgorithm = digestAlgorithm;
        }

        /**
         * Return the algorithm for the underlying digest these parameters will use.
         *
         * @return the digest algorithm
         */
        public FipsDigestAlgorithm getDigestAlgorithm()
        {
            return digestAlgorithm;
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public Parameters withDigestAlgorithm(FipsDigestAlgorithm digestAlgorithm)
        {
            return new Parameters(digestAlgorithm);
        }
    }

    /**
     * Parameters for DSA domain parameter generation.
     */
    public static final class DomainGenParameters
        extends FipsParameters
    {
        private final int L;
        private final int N;
        private final int certainty;

        private final BigInteger p;
        private final BigInteger q;
        private final byte[] seed;
        private final int usageIndex;

        /**
         * Construct just from strength (L) with a default value for N (160 for 1024, 256 for greater)
         * and a default certainty.
         *
         * @param strength desired length of prime P in bits (the effective key size).
         */
        public DomainGenParameters(int strength)
        {
            this(strength, (strength > 1024) ? 256 : 160, PrimeCertaintyCalculator.getDefaultCertainty(strength));      // Valid N for 2048/3072 , N for 1024
        }

        /**
         * Construct just from strength (L) with a default value for N (160 for 1024, 256 for greater).
         *
         * @param strength desired length of prime P in bits (the effective key size).
         * @param certainty certainty level for prime number generation.
         */
        public DomainGenParameters(int strength, int certainty)
        {
            this(strength, (strength > 1024) ? 256 : 160, certainty);            // Valid N for 2048/3072 , N for 1024
        }

        /**
         * Construct without a usage index, this will do a random construction of G.
         *
         * @param L desired length of prime P in bits (the effective key size).
         * @param N desired length of prime Q in bits.
         * @param certainty certainty level for prime number generation.
         */
        public DomainGenParameters(int L, int N, int certainty)
        {
            this(L, N, certainty, null, null, null, -1);
        }

        /**
         * Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
         *
         * @param L desired length of prime P in bits (the effective key size).
         * @param N desired length of prime Q in bits.
         * @param certainty certainty level for prime number generation.
         * @param usageIndex a valid usage index.
         */
        public DomainGenParameters(int L, int N, int certainty, int usageIndex)
        {
            this(L, N, certainty, null, null, null, usageIndex);
        }

        /**
         * Construct from initial prime values, this will do a random construction of G.
         *
         * @param p the prime P.
         * @param q the prime Q.
         */
        public DomainGenParameters(BigInteger p, BigInteger q)
        {
            this(p.bitLength(), q.bitLength(), 0, p, q, null, -1);
        }

        /**
         * Construct for a specific usage index and initial prime values - this has the effect of using verifiable canonical generation of G.
         *
         * @param p the prime P.
         * @param q the prime Q.
         * @param seed seed used in the generation of (p, q).
         * @param usageIndex a valid usage index.
         */
        public DomainGenParameters(BigInteger p, BigInteger q, byte[] seed, int usageIndex)
        {
            this(p.bitLength(), q.bitLength(), 0, p, q, Arrays.clone(seed), usageIndex);
        }

        DomainGenParameters(int L, int N, int certainty, BigInteger p, BigInteger q, byte[] seed, int usageIndex)
        {
            super(ALGORITHM);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (p == null && certainty < PrimeCertaintyCalculator.getDefaultCertainty(L))
                {
                    throw new FipsUnapprovedOperationError("Prime generation certainty " + certainty + " inadequate for parameters of " + L + " bits", this.getAlgorithm());
                }
            }

            if (usageIndex > 255)
            {
                throw new IllegalArgumentException("Usage index must be in range 0 to 255 (or -1 to ignore)");
            }

            this.L = L;
            this.N = N;
            this.certainty = certainty;
            this.p = p;
            this.q = q;
            this.seed = seed;
            this.usageIndex = usageIndex;
        }
    }
    
    /**
     * Domain parameter generator for DSA.
     */
    public static final class DomainParametersGenerator
    {
        private final SecureRandom random;
        private final DomainGenParameters parameters;
        private final FipsDigestAlgorithm digestAlgorithm;

        /**
         * Default constructor using SHA-256 as the digest.
         *
         * @param parameters domain generation parameters.
         * @param random a source of randomness for the parameter generation.
         */
        public DomainParametersGenerator(DomainGenParameters parameters, SecureRandom random)
        {
            this(FipsSHS.Algorithm.SHA256, parameters, random);
        }

        /**
         * Base constructor.
         *
         * @param digestAlgorithm digest to use in prime calculations.
         * @param parameters domain generation parameters.
         * @param random a source of randomness for the parameter generation.
         */
        public DomainParametersGenerator(FipsDigestAlgorithm digestAlgorithm, DomainGenParameters parameters, SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int effSizeInBits = parameters.L;

                if (effSizeInBits != 2048 && effSizeInBits != 3072)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create parameters with unapproved key size [" + effSizeInBits + "]", ALGORITHM);
                }

                Utils.validateRandom(random, Utils.getAsymmetricSecurityStrength(effSizeInBits), ALGORITHM, "Attempt to create parameters with unapproved RNG");
            }

            this.digestAlgorithm = digestAlgorithm;
            this.parameters = parameters;
            this.random = random;
        }

        /**
         * Generate a new set of DSA domain parameters.
         *
         * @return a new set of DSADomainParameters
         */
        public DSADomainParameters generateDomainParameters()
        {
            if (parameters.p != null)
            {
                if (parameters.seed != null && parameters.usageIndex >= 0)
                {
                    BigInteger g = DsaParametersGenerator.calculateGenerator_FIPS186_3_Verifiable(FipsSHS.createDigest(digestAlgorithm), parameters.p, parameters.q, parameters.seed, parameters.usageIndex);

                    return new DSADomainParameters(parameters.p, parameters.q, g, new DSAValidationParameters(parameters.seed, -1, parameters.usageIndex));
                }
                else
                {
                    BigInteger g = DsaParametersGenerator.calculateGenerator_FIPS186_3_Unverifiable(parameters.p, parameters.q, random);

                    return new DSADomainParameters(parameters.p, parameters.q, g, null);
                }
            }
            else
            {
                DsaParametersGenerator pGen = new DsaParametersGenerator(FipsSHS.createDigest(digestAlgorithm));

                DsaParameterGenerationParameters params = new DsaParameterGenerationParameters(
                    parameters.L, parameters.N, parameters.certainty, random, parameters.usageIndex);
                pGen.init(params);

                DsaParameters p = pGen.generateParameters();

                DsaValidationParameters validationParameters = p.getValidationParameters();

                return new DSADomainParameters(p.getP(), p.getQ(), p.getG(), new DSAValidationParameters(validationParameters.getSeed(), validationParameters.getCounter(), validationParameters.getUsageIndex()));
            }
        }
    }

    /**
     * Domain parameter validator for DSA.
     */
    public static final class DomainParametersValidator
    {
        private final Version version;
        private final FipsDigestAlgorithm digestAlgorithm;
        private final SecureRandom random;
        /**
         * Base constructor - for 186-4
         *
         * @param digestAlgorithm digest to use in prime calculations.
         * @param random source of randomness for prime number testing.
         */
        public DomainParametersValidator(FipsDigestAlgorithm digestAlgorithm, SecureRandom random)
        {
            this(Version.FIPS_PUB_186_4, digestAlgorithm, random);
        }

        /**
         * Base constructor.
         *
         * @param version the version of DSS the validator is for.
         * @param digestAlgorithm digest to use in prime calculations.
         * @param random source of randomness for prime number testing.
         */
        public DomainParametersValidator(Version version, FipsDigestAlgorithm digestAlgorithm, SecureRandom random)
        {
            if (Version.FIPS_PUB_186_2 == version && digestAlgorithm != FipsSHS.Algorithm.SHA1)
            {
                throw new IllegalArgumentException("186-2 can only validate with SHA-1");
            }

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateRandom(random, "FIPS SecureRandom required for DSA parameter validation in approved mode.");
            }

            this.version = version;
            this.digestAlgorithm = digestAlgorithm;
            this.random = random;
        }

        private static int getMinimumIterations(int L)
        {
            // Values based on FIPS 186-4 C.3 Table C.1
            return L <= 1024 ? 40 : (48 + 8 * ((L - 1) / 1024));
        }

        /**
         * Validate P and Q against the passed in seed and counter.
         *
         * @param p the prime P.
         * @param q the prime Q.
         * @param seed the seed P and Q were derived from.
         * @param counter the number of iterations required to derive P.
         * @return true if the P and Q values are the expected ones, false otherwise.
         */
        public boolean isValidPAndQ(BigInteger p, BigInteger q, byte[] seed, int counter)
        {
            Digest hash = FipsSHS.createDigest(digestAlgorithm);

            if (Version.FIPS_PUB_186_2 == version)
            {
                if (p.bitLength() != 1024 || q.bitLength() != 160 || counter > 4095)
                {
                    return false;
                }

                if (seed.length < 20)
                {
                    return false;
                }

                BigInteger computed_q = digest(hash, seed).xor(digest(hash, seedPlus1(seed)));

                computed_q = computed_q.setBit(0).setBit(159);

                if (!q.equals(computed_q) || !isProbablePrime(q, getMinimumIterations(1024)))
                {
                    return false;
                }

                BigInteger extra = BigInteger.ONE.shiftLeft(64);

                int i = 0;
                byte[] offset = Arrays.clone(seed);
                inc(offset);

                boolean computedPIsPrime = false;
                BigInteger computed_p = null;
                while (i <= counter)
                {
                    BigInteger W = BigInteger.ZERO;
                    for (int j = 0; j <= 5; j++)
                    {
                        inc(offset);
                        W = W.add(digest(hash, offset).shiftLeft(160 * j));
                    }
                    // (V[6] mod 2**63) * 2**960
                    inc(offset);
                    W = W.add(
                        digest(hash, offset).mod(extra).shiftLeft(160 * 6));

                    BigInteger X = W.setBit(1023);
                    BigInteger c = X.mod(q.shiftLeft(1));

                    computed_p = X.subtract(c.subtract(BigInteger.ONE));

                    if (computed_p.bitLength() == 1024)
                    {
                        if (isProbablePrime(computed_p, getMinimumIterations(1024)))
                        {
                            computedPIsPrime = true;
                            break;
                        }
                    }
                    i++;
                }

                if (i != counter || !p.equals(computed_p) || !computedPIsPrime)
                {
                    return false;
                }
            }
            else
            {
                int L = p.bitLength();
                int N = q.bitLength();

                if (!(L == 1024 && N == 160)
                    && !(L == 2048 && N == 224)
                    && !(L == 2048 && N == 256)
                    && !(L == 3072 && N == 256))
                {
                    return false;
                }

                if (counter > (4 * L - 1))
                {
                    return false;
                }

                if (seed.length * 8 < N)
                {
                    return false;
                }

                BigInteger twoPowNminus1 = BigInteger.ONE.shiftLeft(N - 1);
                BigInteger U = digest(hash, seed).mod(twoPowNminus1);

                BigInteger computed_q = U.setBit(0).setBit(N - 1);

                if (!q.equals(computed_q) || !isProbablePrime(q, getMinimumIterations(L)))
                {
                    return false;
                }

                int outlen = hash.getDigestSize() * 8;

                int n = (L + outlen - 1) / outlen - 1;
                int b = L - (n * outlen);
                BigInteger extra = BigInteger.ONE.shiftLeft(b);

                int i = 0;
                byte[] offset = Arrays.clone(seed);

                boolean computedPIsPrime = false;
                BigInteger computed_p = null;

                while (i <= counter)
                {
                    BigInteger W = BigInteger.ZERO;
                    for (int j = 0; j < n; j++)
                    {
                        inc(offset);
                        W = W.add(digest(hash, offset).shiftLeft(outlen * j));
                    }

                    inc(offset);
                    W = W.add(digest(hash, offset).mod(extra).shiftLeft(outlen * n));

                    BigInteger X = W.setBit(L - 1);
                    BigInteger c = X.mod(q.shiftLeft(1));

                    computed_p = X.subtract(c.subtract(BigInteger.ONE));

                    if (computed_p.bitLength() == L)
                    {
                        if (isProbablePrime(computed_p, getMinimumIterations(L)))
                        {
                            computedPIsPrime = true;
                            break;
                        }
                    }
                    i++;
                }

                if (i != counter || !p.equals(computed_p) || !computedPIsPrime)
                {
                    return false;
                }
            }

            return true;
        }

        /**
         * Do a partial validation of g against p and q.
         *
         * @param p the prime P.
         * @param q the prime Q.
         * @param g the generator G associated with P and Q.
         * @return true if the generator is partially valid, false otherwise.
         */
        public boolean isPartiallyValidG(BigInteger p, BigInteger q, BigInteger g)
        {
            if (BigInteger.valueOf(2).compareTo(g) > 0 || p.subtract(BigInteger.ONE).compareTo(g) < 0)
            {
                return false;
            }

            return g.modPow(q, p).equals(BigInteger.ONE);
        }

        /**
         * Do a full validation of g against p and q by including the seed and index
         * associated with g's related parameters.
         *
         * @param p the prime P.
         * @param q the prime Q.
         * @param seed the domain parameter seed used to generate p and q.
         * @param index the 8 bit usage index for G.
         * @param g the generator G associated with P and Q.
         * @return true if the generator is partially valid, false otherwise.
         */
        public boolean isValidG(BigInteger p, BigInteger q, byte[] seed, int index, BigInteger g)
        {
            Digest hash = FipsSHS.createDigest(digestAlgorithm);

            if ((index >>> 8) != 0)
            {
                return false;
            }

            if (BigInteger.valueOf(2).compareTo(g) > 0 || p.subtract(BigInteger.ONE).compareTo(g) < 0)
            {
                return false;
            }

            if (!g.modPow(q, p).equals(BigInteger.ONE))
            {
                return false;
            }

            BigInteger e = p.subtract(BigInteger.ONE).divide(q);
            int count = 0;

            byte[] counter = new byte[3];
            counter[0] = (byte)index;
            byte[] U = Arrays.concatenate(seed, Hex.decode("6767656E"), counter);

            BigInteger computed_g = null;
            // in our case the wrap check for count terminates at it's largest value.
            while (++count < (1 << 16))
            {
                inc(U);

                computed_g = digest(hash, U).modPow(e, p);

                if (computed_g.compareTo(BigInteger.ONE) <= 0)
                {
                    continue;
                }

                break;
            }

            return g.equals(computed_g);
        }

        private BigInteger digest(Digest hash, byte[] input)
        {
            byte[] res = new byte[hash.getDigestSize()];

            hash.update(input, 0, input.length);

            hash.doFinal(res, 0);

            return new BigInteger(1, res);
        }

        private byte[] seedPlus1(byte[] seed)
        {
            return inc(Arrays.clone(seed));
        }

        private byte[] inc(byte[] value)
        {
            // increment counter by 1.
            for (int i = value.length - 1; i >= 0 && ++value[i] == 0; i--)
            {
                ; // do nothing - pre-increment and test for 0 in counter does the job.
            }

            return value;
        }

        private boolean isProbablePrime(BigInteger x, int iterations)
        {
            /*
             * Primes class for FIPS 186-4 C.3 primality checking
             */
            return !Primes.hasAnySmallFactors(x) && Primes.isMRProbablePrime(x, random, iterations);
        }

        public enum Version
        {
            FIPS_PUB_186_2,
            FIPS_PUB_186_4
        }
    }

    /**
     * DSA key pair generator.
     */
    public static final class KeyPairGenerator
       extends FipsAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricDSAPublicKey, AsymmetricDSAPrivateKey>
    {
        private final DsaKeyPairGenerator engine = new DsaKeyPairGenerator();
        private final DSADomainParameters domainParameters;
        private final DsaKeyGenerationParameters param;

        /**
         * Construct a key pair generator for DSA keys,
         *
         * @param keyGenParameters domain parameters and algorithm for the generated key.
         * @param random a source of randomness for calculating the private value.
         */
        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int effSizeInBits = keyGenParameters.getDomainParameters().getP().bitLength();

                if (effSizeInBits != 2048 && effSizeInBits != 3072)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create key pair with unapproved key size [" + effSizeInBits + "]", keyGenParameters.getAlgorithm());
                }

                Utils.validateKeyPairGenRandom(random, Utils.getAsymmetricSecurityStrength(effSizeInBits), keyGenParameters.getAlgorithm());
            }

            this.domainParameters = keyGenParameters.getDomainParameters();

            this.param = new DsaKeyGenerationParameters(random, getDomainParams(domainParameters));
            this.engine.init(param);
        }

        /**
         * Generate a new DSA key pair.
         *
         * @return a new AsymmetricKeyPair containing a DSA key pair.
         */
        @Override
        public AsymmetricKeyPair<AsymmetricDSAPublicKey, AsymmetricDSAPrivateKey> generateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            DsaPublicKeyParameters pubKey = (DsaPublicKeyParameters)kp.getPublic();
            DsaPrivateKeyParameters prvKey = (DsaPrivateKeyParameters)kp.getPrivate();

            FipsAlgorithm algorithm = this.getParameters().getAlgorithm();

            // FSM_STATE:5.3, "DSA PAIRWISE CONSISTENCY TEST", "The module is performing DSA Pairwise Consistency self-test"
            // FSM_TRANS:5.DSA.0,"CONDITIONAL TEST", "DSA PAIRWISE CONSISTENCY TEST", "Invoke DSA Pairwise Consistency test"
            validateKeyPair(kp);
            // FSM_TRANS:5.DSA.1,"DSA PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "DSA Pairwise Consistency test successful"

            return new AsymmetricKeyPair<AsymmetricDSAPublicKey, AsymmetricDSAPrivateKey>(new AsymmetricDSAPublicKey(algorithm, domainParameters, pubKey.getY()), new AsymmetricDSAPrivateKey(algorithm, domainParameters, prvKey.getX()));
        }
    }

    /**
     * Operator factory for creating DSA based signing and verification operators.
     */
    public static final class OperatorFactory
        extends FipsSignatureOperatorFactory<Parameters>
    {
        /**
         * Return a generator of DSA signatures. Note this operator needs to be associated with a SecureRandom to be
         * fully initialised.
         *
         * @param key the key to initialize the signature generator with.
         * @param parameters parameters required to configure the generation.
         * @return an OutputSignerUsingSecureRandom.
         */
        @Override
        public FipsOutputSignerUsingSecureRandom<Parameters> createSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            DsaSigner dsaSigner = ENGINE_PROVIDER.createEngine();
            Digest digest = (parameters.digestAlgorithm != null) ? FipsSHS.createDigest(parameters.digestAlgorithm) : new NullDigest();

            AsymmetricDSAPrivateKey k = (AsymmetricDSAPrivateKey)key;

            final DsaPrivateKeyParameters privateKeyParameters = getLwKey(k);

            int effSizeInBits = privateKeyParameters.getParameters().getP().bitLength();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (effSizeInBits != 2048 && effSizeInBits != 3072)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create signer with unapproved keysize [" + effSizeInBits + "]", ALGORITHM);
                }
            }

            return new DSAOutputSigner<Parameters>(dsaSigner, digest, parameters, new DSAOutputSigner.Initializer()
            {
                  public void initialize(org.bouncycastle.crypto.internal.DSA signer, SecureRandom random)
                  {
                       signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                  }
            });
        }

        /**
         * Create a verifier for DSA signatures.
         *
         * @param key the key to initialize the verifier with.
         * @param parameters parameters required to configure the verification.
         * @return an OutputVerifier.
         */
        @Override
        public FipsOutputVerifier<Parameters> createVerifier(AsymmetricPublicKey key, final Parameters parameters)
        {
            DsaSigner dsaSigner = ENGINE_PROVIDER.createEngine();
            Digest digest = (parameters.digestAlgorithm != null) ? FipsSHS.createDigest(parameters.digestAlgorithm) : new NullDigest();

            AsymmetricDSAPublicKey k = (AsymmetricDSAPublicKey)key;

            DsaPublicKeyParameters publicKeyParameters = new DsaPublicKeyParameters(k.getY(), getDomainParams(k.getDomainParameters()));

            int effSizeInBits = publicKeyParameters.getParameters().getP().bitLength();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (effSizeInBits != 1024 && effSizeInBits != 2048 && effSizeInBits != 3072)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create verifier with unapproved keysize [" + effSizeInBits + "]", ALGORITHM);
                }
            }

            dsaSigner.init(false, publicKeyParameters);

            return new DSAOutputVerifier<Parameters>(dsaSigner, digest, parameters);
        }
    }

    private static class DsaProvider
        extends FipsEngineProvider<DsaSigner>
    {
        public DsaSigner createEngine()
        {
            // We do this using a pair-wise consistency test as per the IG 2nd March 2015, Section 9.4
           return SelfTestExecutor.validate(ALGORITHM, new DsaSigner(), new VariantKatTest<DsaSigner>()
            {
                @Override
                void evaluate(DsaSigner signer)
                    throws Exception
                {
                    BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);

                    BigInteger p = new BigInteger(
                        "C196BA05AC29E1F9C3C72D56DFFC6154" +
                            "A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A06" +
                            "7CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE4" +
                            "28782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE6" +
                            "19ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1" +
                            "E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD9" +
                            "2D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BF" +
                            "FAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E" +
                            "5320121496DC65B3930E38047294FF877831A16D5228418D" +
                            "E8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A040" +
                            "2A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);

                    BigInteger g = new BigInteger(
                        "A59A749A11242C58C894E9E5A91804E8" +
                            "FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35F" +
                            "C9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E50" +
                            "48B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B" +
                            "6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B715959" +
                            "2E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E574" +
                            "5EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDF" +
                            "D049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E69" +
                            "5515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE" +
                            "7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED20" +
                            "0AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

                    DsaKeyPairGenerator kpGen = new DsaKeyPairGenerator();

                    kpGen.init(new DsaKeyGenerationParameters(
                        new TestRandomBigInteger(Hex.decode("947813B589EDBA642411AD79205E43CE9B859327A4F84CF4B02628DB058A7B22771EA1852903711B")),
                        new DsaParameters(p, q, g)));

                    AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                    signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
                        new FixedSecureRandom.BigInteger("735959CC4463B8B440E407EECA8A473BF6A6D1FE657546F67D401F05"),
                        new FixedSecureRandom.Data(Hex.decode("01020304")))));

                    byte[] msg = Hex.decode("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7");

                    BigInteger[] sig = signer.generateSignature(msg);

                    signer.init(false, kp.getPublic());

                    if (!signer.verifySignature(msg, sig[0], sig[1]))
                    {
                        fail("KAT signature not verified");
                    }
                }
            });
        }
    }
}
