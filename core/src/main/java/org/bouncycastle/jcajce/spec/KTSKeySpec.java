package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.util.Arrays;

/**
 * Base KeySpec for creating the agreed key value in a KTS key exchange such as RSA-KEMs
 */
public class KTSKeySpec
    implements KeySpec
{
    public static final FipsKDF.AgreementKDFParametersBuilder KDF2 = FipsKDF.X963;
    public static final FipsKDF.AgreementKDFParametersBuilder KDF3 = FipsKDF.CONCATENATION;

    private final String keyAlgorithmName;
    private final int keySize;
    private final String macAlgorithm;
    private final int macKeySizeInBits;
    private final AlgorithmParameterSpec parameterSpec;
    private final AlgorithmIdentifier kdfAlgorithm;
    private byte[] otherInfo;

    KTSKeySpec(String keyAlgorithmName, int keySize, String macAlgorithm, int macKeySizeInBits,
               AlgorithmParameterSpec parameterSpec, AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo)
    {
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySize = keySize;
        this.macAlgorithm = macAlgorithm;
        this.macKeySizeInBits = macKeySizeInBits;
        this.parameterSpec = parameterSpec;
        this.kdfAlgorithm = kdfAlgorithm;
        this.otherInfo = otherInfo;
    }

    /**
     * Return the name of the algorithm for the secret key this key spec should produce.
     *
     * @return the key algorithm.
     */
    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }

    /**
     * Return the size of the key (in bits) to be calculated by the SecretKeyFactory used with this key spec.
     *
     * @return length in bits of the key to be calculated.
     */
    public int getKeySize()
    {
        return keySize;
    }

    /**
     * Return the name of the MAC algorithm for the MAC key this key spec should recover (if any).
     *
     * @return the MAC key algorithm, null if not present.
     */
    public String getMacAlgorithmName()
    {
        return macAlgorithm;
    }

    /**
     * Return the size of the key (in bits) to be taken from the extracted secret.
     *
     * @return length in bits of the MAC key to be recovered, 0 if not present.
     */
    public int getMacKeySize()
    {
        return macKeySizeInBits;
    }

    /**
     * Return the algorithm parameter spec to be applied with the private key when the encapsulation is decrypted.
     *
     * @return the algorithm parameter spec to be used with the private key.
     */
    public AlgorithmParameterSpec getParameterSpec()
    {
        return parameterSpec;
    }

    /**
     * Return the AlgorithmIdentifier for the KDF to do key derivation after extracting the secret.
     *
     * @return the AlgorithmIdentifier for the SecretKeyFactory's KDF.
     */
    public AlgorithmIdentifier getKdfAlgorithmId()
    {
        return kdfAlgorithm;
    }

    /**
     * Return the otherInfo data for initialising the KDF.
     *
     * @return the otherInfo data.
     */
    public byte[] getOtherInfo()
    {
        return Arrays.clone(otherInfo);
    }

    static AlgorithmIdentifier createAlgId(FipsKDF.AgreementKDFParametersBuilder kdfParamSource)
    {
        if (kdfParamSource.getAlgorithm().getName().startsWith(KDF2.getAlgorithm().getName()))
        {
            return new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2, new AlgorithmIdentifier(PrfUtils.getObjectIdentifier(kdfParamSource.getPRF().getAlgorithm())));
        }
        else if (kdfParamSource.getAlgorithm().getName().startsWith(KDF3.getAlgorithm().getName()))
        {
            return new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(PrfUtils.getObjectIdentifier(kdfParamSource.getPRF().getAlgorithm())));
        }
        else
        {
            throw new IllegalArgumentException("kdfAlgorithm must be one of KDF2 or KDF3");
        }
    }

    static byte[] copyOtherInfo(byte[] otherInfo)
    {
        return (otherInfo == null) ? new byte[0] : Arrays.clone(otherInfo);
    }
}
