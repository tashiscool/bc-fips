package org.bouncycastle.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.fips.FipsOperationError;
import org.bouncycastle.crypto.internal.Permissions;

/**
 * Basic class describing a secret key implementation. The key will be zeroized explicitly on
 * garbage collection and is protected from being shared between approved an un-approved threads.
 * <p>
 * <b>Note</b>: it the module is run under the SecurityManager only invokers with CryptoServicesPermission.FIPS_MODE_EXPORT_SECRET_KEY
 * permission can successfully call the getKeyBytes() method.
 * </p>
 */
public final class SymmetricSecretKey
    implements SymmetricKey
{
    private final boolean    approvedModeOnly;

    private int        hashCode;
    private Algorithm algorithm;
    private byte[] bytes;

    /**
     * Base constructor.
     *
     * @param algorithm the algorithm this secret key is associated with.
     * @param bytes the bytes representing the key's value.
     */
    public SymmetricSecretKey(Algorithm algorithm, byte[] bytes)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.hashCode = calculateHashCode();
        this.bytes = bytes.clone();
    }

    /**
     * Base constructor for a specific algorithm associated with a parameter set.
     *
     * @param parameterSet the parameter set with the algorithm this secret key is associated with.
     * @param bytes the bytes representing the key's value.
     */
    public SymmetricSecretKey(Parameters parameterSet, byte[] bytes)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = parameterSet.getAlgorithm();
        this.hashCode = calculateHashCode();
        this.bytes = bytes.clone();
    }

    /**
     * Return the algorithm this secret key is for.
     *
     * @return the secret keys algorithm.
     */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    private void zeroize()
    {
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = 0;
        }
        bytes = null;
        algorithm = null;
        hashCode = 0;
    }

    /**
     * Return the bytes representing this keys value.
     *
     * See CryptoServicesPermission.FIPS_MODE_EXPORT_SECRET_KEY for the permission associated with this method.
     *
     * @return the bytes making up this key.
     */
    public byte[] getKeyBytes()
    {
        checkApprovedOnlyModeStatus();

        final SecurityManager securityManager = System.getSecurityManager();

        if (securityManager != null)
        {
            securityManager.checkPermission(Permissions.CanOutputSecretKey);
        }

        return bytes.clone();
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof SymmetricSecretKey))
        {
            return false;
        }

        SymmetricSecretKey other = (SymmetricSecretKey)o;

        if (!getAlgorithm().equals(other.getAlgorithm()))
        {
            return false;
        }
        if (!Arrays.equals(bytes, other.bytes))
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        checkApprovedOnlyModeStatus();

        int result = getAlgorithm().hashCode();
        result = 31 * result + Arrays.hashCode(bytes);
        return result;
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        zeroize();       // ZEROIZE: clear key bytes on de-allocation
    }

    final void checkApprovedOnlyModeStatus()
    {
        if (approvedModeOnly != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsOperationError("attempt to use key created in " + ((approvedModeOnly) ? "approved mode" : "unapproved mode") + " in alternate mode.");
        }
    }
}
