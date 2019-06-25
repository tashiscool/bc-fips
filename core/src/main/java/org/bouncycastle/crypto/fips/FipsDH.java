package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.asymmetric.DHValidationParameters;
import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.asymmetric.DSAValidationParameters;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.PrimeCertaintyCalculator;
import org.bouncycastle.crypto.internal.params.DhKeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DhParameters;
import org.bouncycastle.crypto.internal.params.DhPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DhPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.MqvPrivateParameters;
import org.bouncycastle.crypto.internal.params.MqvPublicParameters;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Source class for FIPS approved mode Diffie-Hellman implementations.
 */
public final class FipsDH
{
    private static final int MIN_FIPS_KEY_STRENGTH = 2048;       // 112 bits of security

    static final FipsEngineProvider<DhBasicAgreement> AGREEMENT_PROVIDER;
    static final FipsEngineProvider<MqvBasicAgreement> MQV_PROVIDER;

    private enum Variations
    {
        DH,
        MQV
    }

    /**
     * Basic Diffie-Hellman key marker, can be used for creating general purpose Diffie-Hellman keys.
     */
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("DH");

    private static final FipsAlgorithm ALGORITHM_DH = new FipsAlgorithm("DH", Variations.DH);
    private static final FipsAlgorithm ALGORITHM_MQV = new FipsAlgorithm("DH", Variations.MQV);

    /**
     * Regular Diffie-Hellman algorithm marker.
     */
    public static final AgreementParameters DH = new AgreementParameters();
    /**
     * Regular MQV algorithm marker.
     */
    public static final MQVAgreementParametersBuilder MQV = new MQVAgreementParametersBuilder();

    static
    {
        AGREEMENT_PROVIDER = new AgreementProvider();
        MQV_PROVIDER = new MqvProvider();

        // FSM_STATE:3.DH.0,"FF AGREEMENT KAT", "The module is performing FF Key Agreement verify KAT self-test"
        // FSM_TRANS:3.DH.0,"POWER ON SELF-TEST", "FF AGREEMENT KAT", "Invoke FF Diffie-Hellman/MQV  KAT self-test"
        AGREEMENT_PROVIDER.createEngine();
        MQV_PROVIDER.createEngine();
        // FSM_TRANS:3.DH.1,"FF AGREEMENT KAT", "POWER ON SELF-TEST", "FF Diffie-Hellman/MQV KAT self-test successful completion"

        // FSM_STATE:3.DH.1,"KAS CVL Primitive 'Z' computation KAT", "The module is performing KAS CVL Primitive 'Z' computation KAT verify KAT self-test"
        // FSM_TRANS:3.DH.2,"POWER ON SELF-TEST", "KAS CVL Primitive 'Z' computation KAT", "Invoke KAS CVL Primitive 'Z' computation KAT self-test"
        ffPrimitiveZTest();
        // FSM_TRANS:3.DH.3,"KAS CVL Primitive 'Z' computation KAT", "POWER ON SELF-TEST", "KAS CVL Primitive 'Z' computation KAT self-test successful completion"
    }

    private FipsDH()
    {

    }

    /**
     * Parameters for Diffie-Hellman key pair generation.
     */
    public static final class KeyGenParameters
        extends FipsParameters
    {
        private final DHDomainParameters domainParameters;

        /**
         * Constructor for the default algorithm ID.
         *
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(DHDomainParameters domainParameters)
        {
            this(ALGORITHM, domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID from a parameter set.
         *
         * @param parameters       the parameters containing the algorithm the generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(AgreementParameters parameters, DHDomainParameters domainParameters)
        {
            this(parameters.getAlgorithm(), domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID from an MQV builder.
         *
         * @param builder        the parameters containing the algorithm the generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        public KeyGenParameters(MQVAgreementParametersBuilder builder, DHDomainParameters domainParameters)
        {
            this(builder.getAlgorithm(), domainParameters);
        }

        /**
         * Base constructor for specifying an algorithm ID.
         *
         * @param algorithm        the particular algorithm generated keys are for.
         * @param domainParameters Diffie-Hellman domain parameters any generated keys will be for.
         */
        private KeyGenParameters(FipsAlgorithm algorithm, DHDomainParameters domainParameters)
        {
            super(algorithm);
            this.domainParameters = domainParameters;
        }

        /**
         * Return the Diffie-Hellman domain parameters for this object.
         *
         * @return the Diffie-Hellman domain parameter set.
         */
        public DHDomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * Parameters for Diffie-Hellman based key agreement.
     */
    public static final class AgreementParameters
        extends FipsAgreementParameters
    {
        /**
         * Default constructor which specifies returning the raw secret on agreement calculation.
         */
        AgreementParameters()
        {
            this(null);
        }

        private AgreementParameters(FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM, digestAlgorithm);
        }

        private AgreementParameters(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM, prfAlgorithm, salt);
        }

        private AgreementParameters(FipsAlgorithm agreementAlgorithm, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            super(agreementAlgorithm, kdfType, iv, outputSize);
        }

        /**
         * Add a digest algorithm to process the Z value with.
         *
         * @param digestAlgorithm digest algorithm to use.
         * @return a new parameter set, including the digest algorithm
         */
        public AgreementParameters withDigest(FipsAlgorithm digestAlgorithm)
        {
            return new AgreementParameters(digestAlgorithm);
        }

        /**
         * Add a PRF algorithm and salt to process the Z value with (as in SP 800-56C)
         *
         * @param prfAlgorithm PRF represent the MAC/HMAC algorithm to use.
         * @param salt         the salt to use to initialise the PRF
         * @return a new parameter set, including the digest algorithm
         */
        public AgreementParameters withPRF(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            return new AgreementParameters(prfAlgorithm, salt);
        }

        /**
         * Add a KDF to process the Z value with. The outputSize parameter determines how many bytes
         * will be generated.
         *
         * @param kdfType            KDF algorithm type to use for parameter creation.
         * @param iv                 the iv parameter for KDF initialization.
         * @param outputSize         the size of the output to be generated from the KDF.
         * @return a new parameter set, the KDF definition.
         */
        public AgreementParameters withKDF(FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            return new AgreementParameters(this.getAlgorithm(), kdfType, iv, outputSize);
        }
    }

    /**
     * Initial builder for MQV parameters.
     */
    public static final class MQVAgreementParametersBuilder
        extends FipsParameters
    {
        MQVAgreementParametersBuilder()
        {
            super(ALGORITHM_MQV);
        }

        /**
         * Constructor for DH MQV parameters from an ephemeral public/private key pair. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralKeyPair       our ephemeral public/private key pair.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricKeyPair ephemeralKeyPair, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters((AsymmetricDHPublicKey)ephemeralKeyPair.getPublicKey(), (AsymmetricDHPrivateKey)ephemeralKeyPair.getPrivateKey(), otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for DH MQV parameters which assumes later calculation of our ephemeral public key. This constructor
         * will result in an agreement which returns the raw calculated agreement value, or shared secret.
         *
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }

        /**
         * Constructor for DH MQV parameters which results in an agreement returning the raw value.
         *
         * @param ephemeralPublicKey     our ephemeral public key.
         * @param ephemeralPrivateKey    our ephemeral private key.
         * @param otherPartyEphemeralKey the other party's ephemeral public key.
         */
        public MQVAgreementParameters using(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey)
        {
            return new MQVAgreementParameters(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
        }
    }

    /**
     * Parameters for Diffie-Hellman based key agreement using MQV.
     */
    public static final class MQVAgreementParameters
        extends FipsAgreementParameters
    {
        private final AsymmetricDHPublicKey ephemeralPublicKey;
        private final AsymmetricDHPrivateKey ephemeralPrivateKey;
        private final AsymmetricDHPublicKey otherPartyEphemeralKey;

        private MQVAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_MQV, digestAlgorithm);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private MQVAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            super(ALGORITHM_MQV, prfAlgorithm, salt);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        private MQVAgreementParameters(AsymmetricDHPublicKey ephemeralPublicKey, AsymmetricDHPrivateKey ephemeralPrivateKey, AsymmetricDHPublicKey otherPartyEphemeralKey, FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            super(ALGORITHM_MQV, kdfType, iv, outputSize);

            this.ephemeralPublicKey = ephemeralPublicKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        }

        /**
         * Return our ephemeral public key, if present.
         *
         * @return our ephemeral public key, or null.
         */
        public AsymmetricDHPublicKey getEphemeralPublicKey()
        {
            return ephemeralPublicKey;
        }

        /**
         * Return our ephemeral private key.
         *
         * @return our ephemeral private key.
         */
        public AsymmetricDHPrivateKey getEphemeralPrivateKey()
        {
            return ephemeralPrivateKey;
        }

        /**
         * Return the other party's ephemeral public key.
         *
         * @return the other party's ephemeral public key.
         */
        public AsymmetricDHPublicKey getOtherPartyEphemeralKey()
        {
            return otherPartyEphemeralKey;
        }

        /**
         * Add a digest algorithm to process the Z value with.
         *
         * @param digestAlgorithm digest algorithm to use.
         * @return a new parameter set, including the digest algorithm
         */
        public MQVAgreementParameters withDigest(FipsAlgorithm digestAlgorithm)
        {
            return new MQVAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, digestAlgorithm);
        }

        /**
         * Add a PRF algorithm and salt to process the Z value with (as in SP 800-56C)
         *
         * @param prfAlgorithm PRF represent the MAC/HMAC algorithm to use.
         * @param salt         the salt to use to initialise the PRF
         * @return a new parameter set, including the digest algorithm
         */
        public MQVAgreementParameters withPRF(FipsKDF.PRF prfAlgorithm, byte[] salt)
        {
            return new MQVAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, prfAlgorithm, salt);
        }

        /**
         * Add a KDF to process the Z value with. The outputSize parameter determines how many bytes
         * will be generated.
         *
         * @param kdfType            KDF algorithm type to use for parameter creation.
         * @param iv                 the iv parameter for KDF initialization.
         * @param outputSize         the size of the output to be generated from the KDF.
         * @return a new parameter set, the KDF definition.
         */
        public MQVAgreementParameters withKDF(FipsKDF.AgreementKDFParametersBuilder kdfType, byte[] iv, int outputSize)
        {
            return new MQVAgreementParameters(this.ephemeralPublicKey, this.ephemeralPrivateKey, this.otherPartyEphemeralKey, kdfType, iv, outputSize);
        }
    }

    /**
     * Parameters for generating Diffie-Hellman domain parameters.
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
         * @param strength  desired length of prime P in bits (the effective key size).
         * @param certainty certainty level for prime number generation.
         */
        public DomainGenParameters(int strength, int certainty)
        {
            this(strength, (strength > 1024) ? 256 : 160, certainty);            // Valid N for 2048/3072 , N for 1024
        }

        /**
         * Construct without a usage index, this will do a random construction of G.
         *
         * @param L         desired length of prime P in bits (the effective key size).
         * @param N         desired length of prime Q in bits.
         * @param certainty certainty level for prime number generation.
         */
        public DomainGenParameters(int L, int N, int certainty)
        {
            this(L, N, certainty, null, null, null, -1);
        }

        /**
         * Construct for a specific usage index - this has the effect of using verifiable canonical generation of G.
         *
         * @param L          desired length of prime P in bits (the effective key size).
         * @param N          desired length of prime Q in bits.
         * @param certainty  certainty level for prime number generation.
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
         * @param p          the prime P.
         * @param q          the prime Q.
         * @param seed       seed used in the generation of (p, q).
         * @param usageIndex a valid usage index.
         */
        public DomainGenParameters(BigInteger p, BigInteger q, byte[] seed, int usageIndex)
        {
            this(p.bitLength(), q.bitLength(), 0, p, q, Arrays.clone(seed), usageIndex);
        }

        private DomainGenParameters(int L, int N, int certainty, BigInteger p, BigInteger q, byte[] seed, int usageIndex)
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
     * Generator class for Diffie-Hellman domain parameters.
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
         * @param random     a source of randomness for the parameter generation.
         */
        public DomainParametersGenerator(DomainGenParameters parameters, SecureRandom random)
        {
            this(FipsSHS.Algorithm.SHA256, parameters, random);
        }

        /**
         * Base constructor.
         *
         * @param digestAlgorithm digest to use in prime calculations.
         * @param parameters      domain generation parameters.
         * @param random          a source of randomness for the parameter generation.
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
         * Generate a new set of Diffie-Hellman domain parameters.
         *
         * @return a new set of DHDomainParameters
         */
        public DHDomainParameters generateDomainParameters()
        {
            if (parameters.L < MIN_FIPS_KEY_STRENGTH)
            {
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    throw new FipsUnapprovedOperationError("Requested DH parameter strength too small for approved mode: " + parameters.L);
                }

                DhParametersGenerator pGen = new DhParametersGenerator();

                pGen.init(parameters.L, parameters.certainty, random);

                DhParameters p = pGen.generateParameters();

                return new DHDomainParameters(p.getP(), p.getQ(), p.getG(), p.getJ(), null);
            }

            FipsDSA.DomainGenParameters params = new FipsDSA.DomainGenParameters(parameters.L, parameters.N, parameters.certainty, parameters.p, parameters.q, parameters.seed, parameters.usageIndex);
            FipsDSA.DomainParametersGenerator pGen = new FipsDSA.DomainParametersGenerator(digestAlgorithm, params, random);

            DSADomainParameters domainParameters = pGen.generateDomainParameters();
            DSAValidationParameters vParams = domainParameters.getValidationParameters();

            if (vParams != null)
            {
                return new DHDomainParameters(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), null, new DHValidationParameters(vParams.getSeed(), vParams.getCounter(), vParams.getUsageIndex()));
            }
            else
            {
                return new DHDomainParameters(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG());
            }
        }
    }

    /**
     * Key pair generator for Diffie-Hellman key pairs.
     */
    public static final class KeyPairGenerator
        extends FipsAsymmetricKeyPairGenerator
    {
        private final DhKeyPairGenerator engine = new DhKeyPairGenerator();
        private final DHDomainParameters domainParameters;
        private final DhKeyGenerationParameters param;

        /**
         * Construct a key pair generator for Diffie-Hellman keys,
         *
         * @param keyGenParameters domain parameters and algorithm for the generated key.
         * @param random           a source of randomness for calculating the private value.
         */
        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int sizeInBits = keyGenParameters.domainParameters.getP().bitLength();
                if (sizeInBits < MIN_FIPS_KEY_STRENGTH)
                {
                    throw new FipsUnapprovedOperationError("Attempt to create key of less than " + MIN_FIPS_KEY_STRENGTH + " bits", keyGenParameters.getAlgorithm());
                }

                Utils.validateKeyPairGenRandom(random, Utils.getAsymmetricSecurityStrength(sizeInBits), ALGORITHM);
            }

            this.param = new DhKeyGenerationParameters(random, getDomainParams(keyGenParameters.getDomainParameters()));
            this.domainParameters = keyGenParameters.getDomainParameters();
            this.engine.init(param);
        }

        /**
         * Generate a new Diffie-Hellman key pair.
         *
         * @return a new AsymmetricKeyPair containing a Diffie-Hellman key pair.
         */
        @Override
        public AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey> generateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            DhPublicKeyParameters pubKey = (DhPublicKeyParameters)kp.getPublic();
            DhPrivateKeyParameters prvKey = (DhPrivateKeyParameters)kp.getPrivate();

            FipsAlgorithm algorithm = (FipsAlgorithm)this.getParameters().getAlgorithm();


            // FSM_STATE:5.6, "DH PAIRWISE CONSISTENCY TEST", "The module is performing DH Pairwise Consistency self-test"
            // FSM_TRANS:5.DH.0,"CONDITIONAL TEST", "DH PAIRWISE CONSISTENCY TEST", "Invoke DH Pairwise Consistency test"
            validateKeyPair(algorithm, kp);
            // FSM_TRANS:5.DH.1,"DH PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "DH Pairwise Consistency test successful"
            // FSM_TRANS:5.DH.2,"DH PAIRWISE CONSISTENCY TEST", "SOFT ERROR", "DH Pairwise Consistency test failed"

            return new AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey>(new AsymmetricDHPublicKey(algorithm, domainParameters, pubKey.getY()), new AsymmetricDHPrivateKey(algorithm, domainParameters, prvKey.getX()));
        }
    }

    /**
     * Factory for Agreement operators based on Diffie-Hellman
     */
    public static final class DHAgreementFactory
        extends FipsAgreementFactory<AgreementParameters>
    {
        /**
         * Return an Agreement operator based on the regular Diffie-Hellman algorithm.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for Diffie-Hellman.
         */
        @Override
        public FipsAgreement<AgreementParameters> createAgreement(AsymmetricPrivateKey key, final AgreementParameters parameters)
        {
            AsymmetricDHPrivateKey dhKey = (AsymmetricDHPrivateKey)key;
            DhPrivateKeyParameters lwDhKey = getLwKey(dhKey);

            final DhBasicAgreement dh = AGREEMENT_PROVIDER.createEngine();

            dh.init(lwDhKey);

            return new FipsAgreement<AgreementParameters>()
            {
                @Override
                public AgreementParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricDHPublicKey dhKey = (AsymmetricDHPublicKey)key;
                    DhPublicKeyParameters lwDhKey = new DhPublicKeyParameters(dhKey.getY(), getDomainParams(dhKey.getDomainParameters()));

                    int length = dh.getFieldSize();
                    BigInteger z = dh.calculateAgreement(lwDhKey);
                    byte[] zBytes = BigIntegers.asUnsignedByteArray(length, z);

                    return FipsKDF.processZBytes(zBytes, parameters);
                }
            };
        }
    }

    /**
     * Factory for Agreement operators based on MQV
     */
    public static final class MQVAgreementFactory
        extends FipsAgreementFactory<MQVAgreementParameters>
    {
        /**
         * Return an Agreement operator based on MQV using Diffie-Hellman keys.
         *
         * @param key        the private key to initialize the Agreement with.
         * @param parameters the parameters for configuring the agreement.
         * @return a new Agreement operator for MQV.
         */
        @Override
        public FipsAgreement<MQVAgreementParameters> createAgreement(AsymmetricPrivateKey key, final MQVAgreementParameters parameters)
        {
            AsymmetricDHPrivateKey dhKey = (AsymmetricDHPrivateKey)key;
            DhPrivateKeyParameters lwDHKey = getLwKey(dhKey);

            final MqvBasicAgreement mqv = MQV_PROVIDER.createEngine();

            mqv.init(new MqvPrivateParameters(lwDHKey, parameters.ephemeralPrivateKey == null ? lwDHKey : getLwKey(parameters.ephemeralPrivateKey)));

            return new FipsAgreement<MQVAgreementParameters>()
            {
                @Override
                public MQVAgreementParameters getParameters()
                {
                    return parameters;
                }

                @Override
                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricDHPublicKey dhKey = (AsymmetricDHPublicKey)key;
                    DhPublicKeyParameters lwDhKey = new DhPublicKeyParameters(dhKey.getY(), getDomainParams(dhKey.getDomainParameters()));

                    int length = mqv.getFieldSize();
                    AsymmetricDHPublicKey ephPublicKey = parameters.getOtherPartyEphemeralKey();
                    BigInteger z = mqv.calculateAgreement(new MqvPublicParameters(lwDhKey, new DhPublicKeyParameters(ephPublicKey.getY(), getDomainParams(ephPublicKey.getDomainParameters()))));
                    byte[] zBytes = BigIntegers.asUnsignedByteArray(length, z);

                    return FipsKDF.processZBytes(zBytes, parameters);
                }
            };
        }
    }

    private static void validateKeyPair(FipsAlgorithm algorithm, AsymmetricCipherKeyPair keyPair)
    {
        Variations variation = (algorithm == ALGORITHM) ? Variations.DH : (Variations)algorithm.basicVariation();

        switch (variation)
        {
        case DH:
            SelfTestExecutor.validate(algorithm, keyPair, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    DhBasicAgreement agreement = new DhBasicAgreement();

                    agreement.init(kp.getPrivate());

                    BigInteger agree1 = agreement.calculateAgreement(kp.getPublic());

                    AsymmetricCipherKeyPair testKP = getTestKeyPair(kp);

                    agreement.init(testKP.getPrivate());

                    BigInteger agree2 = agreement.calculateAgreement(testKP.getPublic());

                    agreement.init(kp.getPrivate());

                    BigInteger agree3 = agreement.calculateAgreement(testKP.getPublic());

                    agreement.init(testKP.getPrivate());

                    BigInteger agree4 = agreement.calculateAgreement(kp.getPublic());

                    return !agree1.equals(agree2) && !agree1.equals(agree3) && agree3.equals(agree4);
                }
            });
            break;
        case MQV:
            SelfTestExecutor.validate(algorithm, keyPair, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                    throws Exception
                {
                    MqvBasicAgreement agreement = new MqvBasicAgreement();

                    agreement.init(new MqvPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    BigInteger agree1 = agreement.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)kp.getPublic(), (DhPublicKeyParameters)kp.getPublic()));

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    agreement.init(new MqvPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    BigInteger agree2 = agreement.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)testSKP.getPublic(), (DhPublicKeyParameters)testEKP.getPublic()));

                    agreement.init(new MqvPrivateParameters((DhPrivateKeyParameters)testSKP.getPrivate(), (DhPrivateKeyParameters)testEKP.getPrivate()));

                    BigInteger agree3 = agreement.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)kp.getPublic(), (DhPublicKeyParameters)kp.getPublic()));

                    return !agree1.equals(agree2) && agree2.equals(agree3);
                }
            });
            break;
        default:
            throw new IllegalStateException("Unhandled DH algorithm: " + algorithm.getName());
        }
    }

    private static class AgreementProvider
        extends FipsEngineProvider<DhBasicAgreement>
    {
        public DhBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM_DH, new DhBasicAgreement(), new VariantKatTest<DhBasicAgreement>()
            {
                @Override
                void evaluate(DhBasicAgreement engine)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeyPair();

                    AsymmetricCipherKeyPair testOther = getTestKeyPair(kp);

                    engine.init(kp.getPrivate());

                    BigInteger expected = new BigInteger("8b2ba83764fc961a7aeb335d67aa206c1013be9127e2d37a43fa7fff45dd13d4699173a727f4fc88b66d5f53c8848667c090adb2879501d1f7fe53b430beb220b6cce85c5bff74c61b16dbc788ab1459eec1b6f03455862324210e72f7e1f01a55f464bbd996267d3693cdc61053d87a17cb93f6e5079188377db48774bc9232552440471218ec2834e0e29fcdba7e0b7caf9a8f679c4e4382f83f66f8a4dd61cc5d91d15440f10a0f76c3e3a495e7cc53993ba7fb3231310c79e2b587a10074030f158a560e85c89642da9c883f78947116d8ea0d94bfe77c6fb07a7fca8c524827f5779aa7f5428fec0d282f8aca22dd1d47ed61eb6584b5444c5344ab716e", 16);

                    if (!expected.equals(engine.calculateAgreement(testOther.getPublic())))
                    {
                        fail("KAT DH agreement not verified");
                    }
                }
            });
        }
    }

    private static class MqvProvider
        extends FipsEngineProvider<MqvBasicAgreement>
    {
        public MqvBasicAgreement createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM_MQV, new MqvBasicAgreement(), new VariantKatTest<MqvBasicAgreement>()
            {
                @Override
                void evaluate(MqvBasicAgreement engine)
                    throws Exception
                {
                    AsymmetricCipherKeyPair kp = getKATKeyPair();

                    AsymmetricCipherKeyPair testSKP = getTestKeyPair(kp);
                    AsymmetricCipherKeyPair testEKP = getTestKeyPair(kp);

                    engine.init(new MqvPrivateParameters((DhPrivateKeyParameters)kp.getPrivate(), (DhPrivateKeyParameters)kp.getPrivate()));

                    BigInteger calculated = engine.calculateAgreement(new MqvPublicParameters((DhPublicKeyParameters)testSKP.getPublic(), (DhPublicKeyParameters)testEKP.getPublic()));

                    BigInteger expected = new BigInteger("52b800582b28e89d8ee581014ea4a1bc59cc3cc202562788ac40cbf9b1b11657019b556f112ecc9404b1de17630edcd0b8f9f4075e39624e94074b5060d3e699f726873b16e6ec49bdf689bcc275477da4170c7bbe93bfd5bc32a9556311d3f54d0e534118363deda2e3d25b6213b3d01f218c3f1d237967d128cd5a0f0caca8e287fd599d48ce297c8d92a4b7b2d95950a8ddb0e86e7b9bdc6abab91f758613762d185b2a5f516434f96c1bcba67f47bb780ade54dfa6a4f6a8d130aca76f9b28d77ef5eae1e254e5b61526b8c0fecf11b22e8630ebdd5e95f3902954526bd99eb8735263855b5f4d1ea32f6a0d2895ed292e9bb17a07ba1742a1619f4d95c9", 16);

                    if (!expected.equals(calculated))
                    {
                        fail("KAT DH MQV agreement not verified");
                    }
                }
            });
        }
    }

    private static void ffPrimitiveZTest()
    {
        SelfTestExecutor.validate(ALGORITHM, new VariantInternalKatTest(ALGORITHM)
        {
            @Override
            void evaluate()
                throws Exception
            {
                AsymmetricCipherKeyPair kp = getKATKeyPair();

                DhPrivateKeyParameters priv = (DhPrivateKeyParameters)kp.getPrivate();
                DhPublicKeyParameters pub = (DhPublicKeyParameters)kp.getPublic();

                if (!pub.getY().equals(priv.getParameters().getG().modPow(priv.getX(), priv.getParameters().getP())))
                {
                    fail("FF primitive 'Z' computation failed");
                }
            }
        });
    }

    private static AsymmetricCipherKeyPair getKATKeyPair()
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

        BigInteger x = new BigInteger(
            "80d54802e42ce811d122ce2657c303013fc33c2f08f8ff1a9c4ebfd1", 16);

        BigInteger y = new BigInteger(
            "76277e7f847626c252c76828a6142b75e92aaa69612c789686686f44" +
                "7d7361f58c54dac02f23a672157a239dedefaeadecdd94b8f581ec08" +
                "6d152517532c2a8465983f51a643491ddcc328792c9795674ba630b4" +
                "7f364670432d826e2733bc85a666c64e3607d599b125b79ff5a179c8" +
                "8ceee1972d3da80c77c7652b0dc2930f0bf81be1a782e27f35f82848" +
                "ea0e1f2d4ff6d0c6a739bbc61bdb646d1a189a10421a76c2942254ec" +
                "92e7f7d3bec0b6066eb70c9de6be50409e25f7d0e0b93fcc08a9f269" +
                "4253238c6889a909f22b636924e54f6b12392ddf5016633646476b74" +
                "257ffbb486723f1a3167c93f0e577c4e6d3734f4af38153c76850374" +
                "c067e6c7", 16);

        DhParameters dhParameters = new DhParameters(p, g, q);

        return new AsymmetricCipherKeyPair(new DhPublicKeyParameters(y, dhParameters), new DhPrivateKeyParameters(x, dhParameters));
    }

    private static AsymmetricCipherKeyPair getTestKeyPair(AsymmetricCipherKeyPair kp)
    {
        DhPrivateKeyParameters privKey = (DhPrivateKeyParameters)kp.getPrivate();
        DhParameters dhParams = privKey.getParameters();

        BigInteger testD = privKey.getX().multiply(BigInteger.valueOf(7)).mod(privKey.getX());

        if (testD.compareTo(BigInteger.valueOf(2)) < 0)
        {
            testD = new BigInteger("0102030405060708090a0b0c0d0e0f101112131415161718", 16);
        }

        DhPrivateKeyParameters testPriv = new DhPrivateKeyParameters(testD, dhParams);
        DhPublicKeyParameters testPub = new DhPublicKeyParameters(dhParams.getG().modPow(testD, dhParams.getP()), dhParams);

        return new AsymmetricCipherKeyPair(testPub, testPriv);
    }

    private static DhParameters getDomainParams(DHDomainParameters dhParameters)
    {
        return new DhParameters(dhParameters.getP(), dhParameters.getG(), dhParameters.getQ(), dhParameters.getM(), dhParameters.getL(), dhParameters.getJ());
    }

    private static DhPrivateKeyParameters getLwKey(final AsymmetricDHPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<DhPrivateKeyParameters>()
        {
            public DhPrivateKeyParameters run()
            {
                return new DhPrivateKeyParameters(privKey.getX(), getDomainParams(privKey.getDomainParameters()));
            }
        });
    }
}
