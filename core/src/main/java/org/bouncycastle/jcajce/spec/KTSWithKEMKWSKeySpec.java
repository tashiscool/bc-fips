package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;

/**
 * KeySpec for use with the RSA-KTS-KEM-KWS SecretKeyFactory. The spec can be used to create a secret key with an encapsulation
 * using the RSA-KEM-KWS format described in SP 800-56B,
 */
public class KTSWithKEMKWSKeySpec
    implements KeySpec
{
    private final KTSKeySpec ktsKeySpec;
    private final String transportedKeyAlgorithm;
    private final int transportedKeySizeInBits;

    /**
     * Base constructor.
     *
     * @param ktsKeySpec the spec for the KTS step which generates the wrapping key and the optional MAC key.
     * @param transportedKeyAlgorithm secret key algorithm for created secret key
     * @param transportedKeySizeInBits secret key key size in bits for transported key.
     */
    public KTSWithKEMKWSKeySpec(KTSKeySpec ktsKeySpec, String transportedKeyAlgorithm, int transportedKeySizeInBits)
    {
        this.ktsKeySpec = ktsKeySpec;
        this.transportedKeyAlgorithm = transportedKeyAlgorithm;
        this.transportedKeySizeInBits = transportedKeySizeInBits;
    }

    /**
     * Return the base spec for the KTS step.
     *
     * @return the base KTS spec.
     */
    public KTSKeySpec getKTSKeySpec()
    {
        return ktsKeySpec;
    }

    /**
     * Return the algorithm name for the transported key.
     *
     * @return transported key algorithm name.
     */
    public String getTransportedKeyAlgorithm()
    {
        return transportedKeyAlgorithm;
    }

    /**
     * Return the key size (in bits) of the transported key.
     *
     * @return the key size (in bits) of the transported key.
     */
    public int getTransportedKeySize()
    {
        return transportedKeySizeInBits;
    }
}
