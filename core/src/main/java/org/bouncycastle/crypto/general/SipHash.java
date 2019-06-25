package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.macs.TruncatingMac;

/**
 * Source class for implementations of SipHash based algorithms
 */
public final class SipHash
{
    private SipHash()
    {

    }

    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("SipHash");

    public static final GeneralAlgorithm SIPHASH_2_4 = new GeneralAlgorithm("SipHash-2-4");
    public static final GeneralAlgorithm SIPHASH_4_8 = new GeneralAlgorithm("SipHash-4-8");

    /**
     * Parameters for SipHash MAC modes.
     */
    public static final class AuthParameters
        extends GeneralParameters<GeneralAlgorithm>
        implements AuthenticationParameters<AuthParameters>
    {
        private final int macSizeInBits;

        private AuthParameters(GeneralAlgorithm algorithm, int macSizeInBits)
        {
            super(algorithm);
            this.macSizeInBits = macSizeInBits;
        }

        public AuthParameters()
        {
            this(SIPHASH_2_4);
        }

        public AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, 64);
        }

        public int getMACSizeInBits()
        {
            return macSizeInBits;
        }

        public AuthParameters withMACSize(int macSizeInBits)
        {
            return new AuthParameters(this.getAlgorithm(), macSizeInBits);
        }
    }

    /**
     * SipHash key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private final GeneralAlgorithm algorithm;
        private final SecureRandom random;

        public KeyGenerator(SecureRandom random)
        {
            this(ALGORITHM, random);
        }

        public KeyGenerator(GeneralAlgorithm algorithm, SecureRandom random)
        {
            this.algorithm = algorithm;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, 128));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for producing SipHash MAC calculators.
     */
    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            Mac mac = getMac(parameters);
            if (mac.getMacSize() != (parameters.getMACSizeInBits() + 7) / 8)
            {
                mac = new TruncatingMac(mac, parameters.macSizeInBits);
            }

            mac.init(Utils.getKeyParameter(validateKey(key, parameters)));

            return mac;
        }

        private Mac getMac(AuthParameters parameters)
        {
            Mac mac;
            if (parameters.getAlgorithm() == SIPHASH_2_4)
            {
                mac = new SipHashEngine(2, 4);
            }
            else if (parameters.getAlgorithm() == SIPHASH_4_8)
            {
                mac = new SipHashEngine(4, 8);
            }
            else
            {
                throw new IllegalArgumentException("Unknown algorithm passed to createMAC: " + parameters.getAlgorithm());
            }
            return mac;
        }


        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return getMac(parameters).getMacSize();
        }

    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, org.bouncycastle.crypto.Parameters parameters)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("SipHash key must be of length 128 bits");
        }

        Algorithm algorithm = key.getAlgorithm();

        if (algorithm != ALGORITHM)
        {
            if (algorithm != parameters.getAlgorithm())
            {
                throw new IllegalKeyException("Key not for appropriate algorithm");
            }
        }

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength != 128;
    }
}
