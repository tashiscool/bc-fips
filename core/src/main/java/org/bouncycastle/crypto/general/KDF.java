package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.util.Arrays;

/**
 * Source class for non-FIPS key derivation functions (KDF).
 */
public final class KDF
{
    private KDF()
    {
    }

    /**
     * The SCrypt KDF.
     */
    public static final ScryptParametersBuilder SCRYPT = new ScryptParametersBuilder(new GeneralAlgorithm("SCrypt"));

    /**
     * Parameters builder for the SCrypt key derivation function.
     */
    public static final class ScryptParametersBuilder
        extends GeneralParameters<GeneralAlgorithm>
    {
        ScryptParametersBuilder(GeneralAlgorithm algorithm)
        {
            super(algorithm);
        }

        public ScryptParameters using(byte[] salt, int n, int r, int p, byte[] seed)
        {
            return new ScryptParameters(n, Arrays.clone(seed), r, p, Arrays.clone(salt));
        }

        public ScryptParameters using(byte[] salt, int n, int r, int p, PasswordConverter converter, char[] password)
        {
            return new ScryptParameters(n, converter.convert(password), r, p, Arrays.clone(salt));
        }
    }

    /**
     * Parameters for the SCrypt key derivation function.
     */
    public static final class ScryptParameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        final int n;
        final int r;
        final int p;
        final byte[] salt;
        final byte[] seed;

        private ScryptParameters(int n, byte[] seed, int r, int p, byte[] salt)
        {
            super(SCRYPT.getAlgorithm());

            this.seed = seed;
            this.n = n;
            this.r = r;
            this.p = p;
            this.salt = salt;
        }
    }

    /**
     * Factory for SCrypt KDFs.
     */
    public static final class SCryptFactory
        extends GuardedKDFOperatorFactory<ScryptParameters>
    {
        public KDFCalculator createKDFCalculator(final ScryptParameters params)
        {
             return new KDFCalculator()
             {
                 public ScryptParameters getParameters()
                 {
                     Utils.approveModeCheck(SCRYPT.getAlgorithm());

                     return params;
                 }

                 public void generateBytes(byte[] out)
                 {
                     Utils.approveModeCheck(SCRYPT.getAlgorithm());

                     byte[] tmp = SCryptImpl.generate(params.seed, params.salt, params.n, params.r, params.p, out.length);

                     System.arraycopy(tmp, 0, out, 0, out.length);

                     Arrays.fill(tmp, (byte)0);
                 }

                 public void generateBytes(byte[] out, int outOff, int len)
                 {
                     Utils.approveModeCheck(SCRYPT.getAlgorithm());

                     byte[] tmp = SCryptImpl.generate(params.seed, params.salt, params.n, params.r, params.p, len);

                     System.arraycopy(tmp, 0, out, outOff, len);

                     Arrays.fill(tmp, (byte)0);
                 }
             };
        }
    }
}
