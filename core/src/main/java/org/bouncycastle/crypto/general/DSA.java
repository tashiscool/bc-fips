package org.bouncycastle.crypto.general;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.OutputSignerUsingSecureRandom;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.asymmetric.DSAValidationParameters;
import org.bouncycastle.crypto.fips.FipsDSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.PrimeCertaintyCalculator;
import org.bouncycastle.crypto.internal.params.DsaKeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaParameterGenerationParameters;
import org.bouncycastle.crypto.internal.params.DsaParameters;
import org.bouncycastle.crypto.internal.params.DsaPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.DsaValidationParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for non-FIPS implementations of DSA based algorithms.
 */
public final class DSA
{
    public static final Algorithm ALGORITHM = FipsDSA.ALGORITHM;

    private enum Variations
    {
        DSA,
        DDSA
    }

    public static final Parameters DSA = new Parameters(new GeneralAlgorithm(ALGORITHM.getName(), Variations.DSA), FipsSHS.Algorithm.SHA1);
    public static final Parameters DDSA = new Parameters(new GeneralAlgorithm(ALGORITHM.getName(), Variations.DDSA), FipsSHS.Algorithm.SHA1);

    private DSA()
    {

    }

    /**
     * Parameters for non-FIPS DSA signatures.
     */
    public static final class Parameters
        extends GeneralParameters
    {
        private final DigestAlgorithm digestAlgorithm;

        Parameters(GeneralAlgorithm type, DigestAlgorithm digestAlgorithm)
        {
            super(type);

            if (type.basicVariation() == Variations.DDSA && digestAlgorithm == null)
            {
                throw new IllegalArgumentException("DDSA cannot be used with a NULL digest");
            }

            this.digestAlgorithm = digestAlgorithm;
        }

        /**
         * Return the algorithm for the underlying digest these parameters will use.
         *
         * @return the digest algorithm
         */
        public DigestAlgorithm getDigestAlgorithm()
        {
            return digestAlgorithm;
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public Parameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new Parameters((GeneralAlgorithm)getAlgorithm(), digestAlgorithm);
        }
    }

    /**
     * DSA key pair generation parameters for non-FIPS usages.
     */
    public static final class KeyGenParameters
        extends GeneralParameters
    {
        private final DSADomainParameters domainParameters;

        /**
          * Key Generation parameters for a specific algorithm set.
          *
          * @param parameters parameter set representing the algorithm involved.
          * @param domainParameters the DSA domain parameters.
          */
        public KeyGenParameters(Parameters parameters, DSADomainParameters domainParameters)
        {
            super(parameters.getAlgorithm());
            this.domainParameters = domainParameters;
        }

        /**
         * Base constructor for specific domain parameters.
         *
         * @param domainParameters the EC domain parameters.
         */
        public KeyGenParameters(DSADomainParameters domainParameters)
        {
            super(ALGORITHM);
            this.domainParameters = domainParameters;
        }

        public DSADomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * DSA domain generation parameters for non-FIPS usages.
     */
    public static final class DomainGenParameters
        extends GeneralParameters
    {
        private final int strength;
        private final int certainty;

        public DomainGenParameters(int strength)
        {
            this(strength, PrimeCertaintyCalculator.getDefaultCertainty(strength));
        }

        public DomainGenParameters(int strength, int certainty)
        {
            super(ALGORITHM);
            this.strength = strength;
            this.certainty = certainty;
        }
    }

    /**
     * Generator for DSA domain parameters for non-FIPS usages.
     */
    public static final class DomainParametersGenerator
    {
        private final SecureRandom random;
        private final DomainGenParameters parameters;

        public DomainParametersGenerator(DomainGenParameters parameters, SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Attempt to create unapproved generator in approved only mode.");
            }

            this.parameters = parameters;
            this.random = random;
        }

        public DSADomainParameters generateDomainParameters()
        {
            DsaParametersGenerator pGen;

            if (parameters.strength <= 1024)
            {
                pGen = new DsaParametersGenerator();
            }
            else
            {
                pGen = new DsaParametersGenerator(Register.createDigest(FipsSHS.Algorithm.SHA256));
            }

            DsaParameterGenerationParameters params;

            if (parameters.strength == 1024)
            {
                if (Properties.isOverrideSet("org.bouncycastle.dsa.FIPS186-2for1024bits"))
                {
                    pGen.init(parameters.strength, parameters.certainty, random);
                }
                else
                {
                    params = new DsaParameterGenerationParameters(1024, 160, parameters.certainty, random);
                    pGen.init(params);
                }
            }
            else if (parameters.strength > 1024)
            {
                params = new DsaParameterGenerationParameters(parameters.strength, 256, parameters.certainty, random);
                pGen.init(params);
            }
            else
            {
                pGen.init(parameters.strength, parameters.certainty, random);
            }

            DsaParameters p = pGen.generateParameters();

            DsaValidationParameters validationParameters = p.getValidationParameters();

            return new DSADomainParameters(p.getP(), p.getQ(), p.getG(), new DSAValidationParameters(validationParameters.getSeed(), validationParameters.getCounter(), validationParameters.getUsageIndex()));
        }
    }

    /**
     * DSA key pair generator class for non-FIPS usages.
     */
    public static final class KeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricDSAPublicKey, AsymmetricDSAPrivateKey>
    {
        private final DsaKeyPairGenerator engine = new DsaKeyPairGenerator();
        private final DSADomainParameters domainParameters;
        private final DsaKeyGenerationParameters param;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.domainParameters = keyGenParameters.getDomainParameters();

            this.param = new DsaKeyGenerationParameters(random, getDomainParams(domainParameters));
            this.engine.init(param);
        }

        @Override
        protected AsymmetricKeyPair<AsymmetricDSAPublicKey, AsymmetricDSAPrivateKey> doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            validateKeyPair(kp);

            DsaPublicKeyParameters pubKey = (DsaPublicKeyParameters)kp.getPublic();
            DsaPrivateKeyParameters prvKey = (DsaPrivateKeyParameters)kp.getPrivate();

            Algorithm algorithm = this.getParameters().getAlgorithm();

            return new AsymmetricKeyPair<AsymmetricDSAPublicKey, AsymmetricDSAPrivateKey>(new AsymmetricDSAPublicKey(algorithm, domainParameters, pubKey.getY()), new AsymmetricDSAPrivateKey(algorithm, domainParameters, prvKey.getX()));
        }
    }

    /**
     * Operator factory for creating non-FIPS DSA based signing and verification operators.
     */
    public static final class OperatorFactory
        extends GuardedSignatureOperatorUsingSecureRandomFactory<Parameters>
    {
        @Override
        protected OutputSignerUsingSecureRandom<Parameters> doCreateSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            Digest digest = (parameters.digestAlgorithm != null) ? Register.createDigest(parameters.digestAlgorithm) : new NullDigest();

            DsaSigner dsaSigner;
            if (parameters.getAlgorithm() == DSA.getAlgorithm())
            {
                dsaSigner = new DsaSigner(new RandomDsaKCalculator());
            }
            else
            {
                dsaSigner = new DsaSigner(new HMacDsaKCalculator(Register.createDigest(parameters.digestAlgorithm)));
            }

            AsymmetricDSAPrivateKey k = (AsymmetricDSAPrivateKey)key;

            final DsaPrivateKeyParameters privateKeyParameters = getLwKey(k);

            return new DSAOutputSigner<Parameters>(dsaSigner, digest, parameters, new DSAOutputSigner.Initializer()
            {
                public void initialize(org.bouncycastle.crypto.internal.DSA signer, SecureRandom random)
                {
                    signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                }
            });
        }

        @Override
        protected OutputVerifier<Parameters> doCreateVerifier(AsymmetricPublicKey key, final Parameters parameters)
        {
            Digest digest = (parameters.digestAlgorithm != null) ? Register.createDigest(parameters.digestAlgorithm) : new NullDigest();

            DsaSigner dsaSigner;
            if (parameters.getAlgorithm() == DSA.getAlgorithm())
            {
                dsaSigner = new DsaSigner(new RandomDsaKCalculator());
            }
            else
            {
                dsaSigner = new DsaSigner(new HMacDsaKCalculator(Register.createDigest(parameters.digestAlgorithm)));
            }

            AsymmetricDSAPublicKey k = (AsymmetricDSAPublicKey)key;

            DsaPublicKeyParameters publicKeyParameters = new DsaPublicKeyParameters(k.getY(), getDomainParams(k.getDomainParameters()));

            dsaSigner.init(false, publicKeyParameters);

            return new DSAOutputVerifier<Parameters>(dsaSigner, digest, parameters);
        }
    }

    private static void validateKeyPair(AsymmetricCipherKeyPair kp)
    {
        SelfTestExecutor.validate(ALGORITHM, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
        {
            public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
            {
                final byte[] data = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                DsaSigner signer = new DsaSigner(new RandomDsaKCalculator());

                signer.init(true, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                BigInteger[] rv = signer.generateSignature(data);

                signer.init(false, kp.getPublic());

                signer.verifySignature(data, rv[0], rv[1]);

                return signer.verifySignature(data, rv[0], rv[1]);
            }
        });
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
}
