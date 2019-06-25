package org.bouncycastle.crypto.asymmetric;

import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.util.Properties;

/**
 * Base class for RSA keys.
 * <p>
 * <b>Note</b>: the module attempts to prevent accidental recent use of RSA keys for signing and encryption purposes by associating
 * a specific usage with a modulus. If the module is not running in approved mode this behavior can be overridden by
 * setting the system property "org.bouncycastle.rsa.allow_multi_use" to "true".
 * </p>
 */
public abstract class AsymmetricRSAKey
    implements AsymmetricKey
{
    /**
     * Specific RSA key usages.
     */
    public enum Usage
    {
        /**
         * Key usage signing or verification.
         */
        SIGN_OR_VERIFY,
        /**
         * Key usage encryption or decryption.
         */
        ENCRYPT_OR_DECRYPT
    }

    protected static final AlgorithmIdentifier DEF_ALG_ID = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final Set<ASN1ObjectIdentifier> rsaOids = new HashSet<ASN1ObjectIdentifier>(4);

    static
    {
        rsaOids.add(PKCSObjectIdentifiers.rsaEncryption);
        rsaOids.add(X509ObjectIdentifiers.id_ea_rsa);
        rsaOids.add(PKCSObjectIdentifiers.id_RSAES_OAEP);
        rsaOids.add(PKCSObjectIdentifiers.id_RSASSA_PSS);
        rsaOids.add(PKCSObjectIdentifiers.id_rsa_KEM);
    }

    private final boolean    approvedModeOnly;
    private final KeyMarker  keyMarker;

    private Algorithm algorithm;
    private BigInteger modulus;

    protected final AlgorithmIdentifier rsaAlgIdentifier;

    AsymmetricRSAKey(Algorithm algorithm, BigInteger modulus)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.keyMarker = getKeyMarker(modulus);
        this.modulus = keyMarker.modulus;
        this.rsaAlgIdentifier = DEF_ALG_ID;
    }

    AsymmetricRSAKey(Algorithm algorithm, AlgorithmIdentifier rsaAlgIdentifier, BigInteger modulus)
    {
        ASN1ObjectIdentifier keyAlgorithm = rsaAlgIdentifier.getAlgorithm();

        if (!rsaOids.contains(keyAlgorithm))
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + keyAlgorithm);
        }

        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.rsaAlgIdentifier = rsaAlgIdentifier;
        this.keyMarker = getKeyMarker(modulus);
        this.modulus = keyMarker.modulus;

        if (keyAlgorithm.equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
        {
            keyMarker.canBeUsed(Usage.SIGN_OR_VERIFY);
        }
        else if (keyAlgorithm.equals(PKCSObjectIdentifiers.id_RSAES_OAEP))
        {
            keyMarker.canBeUsed(Usage.ENCRYPT_OR_DECRYPT);
        }
    }

    /**
     * Return the algorithm this RSA key is for.
     *
     * @return the key's algorithm.
     */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the modulus for this RSA key.
     *
     * @return the key's modulus.
     */
    public BigInteger getModulus()
    {
        return modulus;
    }

    /**
     * Check to see if a key can be used for a specific usage. Essentially this will return false if
     * the modulus is associated with a different usage already. The system property "org.bouncycastle.rsa.allow_multi_use"
     * can be set to "true" to override this check.
     *
     * @param usage usage for the RSA key.
     * @return true if the modulus is already associated with the usage, or has not being used already.
     */
    public boolean canBeUsed(Usage usage)
    {
        return Properties.isOverrideSet("org.bouncycastle.rsa.allow_multi_use") || keyMarker.canBeUsed(usage);
    }

    protected void zeroize()
    {
        this.algorithm = null;
        this.modulus = null;
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (approvedModeOnly != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }

    private static WeakHashMap<BigInteger, WeakReference<KeyMarker>> markers = new WeakHashMap<BigInteger, WeakReference<KeyMarker>>();

    static synchronized boolean isAlreadySeen(BigInteger modulus)
    {
        return markers.containsKey(modulus);
    }

    static synchronized KeyMarker getKeyMarker(BigInteger modulus)
    {
        KeyMarker marker = null;

        WeakReference<KeyMarker> markerRef = markers.get(modulus);
        if (markerRef != null)
        {
            marker = markerRef.get();
        }

        if (marker != null)
        {
            return marker;
        }

        marker = new KeyMarker(modulus);

        markerRef = new WeakReference<KeyMarker>(marker);

        markers.put(modulus, markerRef);

        return marker;
    }

    private static class KeyMarker
    {
        private final AtomicReference<Usage> keyUsage = new AtomicReference<Usage>(null);

        private final BigInteger modulus;

        KeyMarker(BigInteger modulus)
        {
            this.modulus = modulus;
        }

        public boolean canBeUsed(Usage usage)
        {
            return keyUsage.compareAndSet(null, usage) || keyUsage.get().equals(usage);
        }
    }
}
