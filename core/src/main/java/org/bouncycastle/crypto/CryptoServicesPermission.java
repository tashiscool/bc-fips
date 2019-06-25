package org.bouncycastle.crypto;

import java.security.Permission;
import java.util.HashSet;
import java.util.Set;

/**
 * Permissions that need to be configured if a SecurityManager is used.
 */
public class CryptoServicesPermission
    extends Permission
{
    /**
     * Allow a caller to export secret/private keys to be from the jar. This permission enables both
     * FIPS_MODE_EXPORT_PRIVATE_KEY and FIPS_MODE_EXPORT_SECRET_KEY.
     */
    public static final String FIPS_EXPORT_KEYS = "exportKeys";

    /**
     * Enable full TLS support for providers like the JSSE. This permission enables
     * FIPS_MODE_TLS_ECDH_ENABLED and FIPS_MODE_TLS_PKCS15_KEY_WRAP_ENABLED.
     */
    public static final String FIPS_TLS_ALGORITHMS_ENABLED = "tlsAlgorithmsEnabled";

    /**
     * Enable unapproved mode as the default.
     */
    public static final String FIPS_MODE_UNAPPROVED_MODE_ENABLED = "unapprovedModeEnabled";

    /**
     * Enable a thread to change its state into approved mode.
     */
    public static final String FIPS_MODE_CHANGE_TO_APPROVED_MODE_ENABLED = "changeToApprovedModeEnabled";

    /**
     * Enable the export of a private key from the jar.
     */
    public static final String FIPS_MODE_EXPORT_PRIVATE_KEY = "exportPrivateKey";
    /**
     * Enable the export of a secret key from the jar.
     */
    public static final String FIPS_MODE_EXPORT_SECRET_KEY = "exportSecretKey";

    /**
     * Enable support for signature algorithms that can take an actual digest as an argument, rather
     * than message to be digested.
     */
    public static final String FIPS_MODE_TLS_NULL_DIGEST_ENABLED = "tlsNullDigestEnabled";

    /**
     * Enable support for PKCS 1.5 RSA encryption to be used for key wrapping.
     */
    public static final String FIPS_MODE_TLS_PKCS15_KEY_WRAP_ENABLED = "tlsPKCS15KeyWrapEnabled";

    /**
     * Enable the setting of global configuration properties. This permission implies THREAD_LOCAL_CONFIG
     */
    public static final String GLOBAL_CONFIG = "globalConfig";

    /**
     * Enable the setting of thread local configuration properties.
     */
    public static final String THREAD_LOCAL_CONFIG = "threadLocalConfig";

    /**
     * Enable the setting of the default SecureRandom.
     */
    public static final String DEFAULT_RANDOM = "defaultRandomConfig";

    private final Set<String> actions = new HashSet<String>();

    public CryptoServicesPermission(String name)
    {
        super(name);

        if (name.equals(FIPS_EXPORT_KEYS))
        {
            this.actions.add(FIPS_MODE_EXPORT_PRIVATE_KEY);
            this.actions.add(FIPS_MODE_EXPORT_SECRET_KEY);
        }
        else if (name.equals(FIPS_TLS_ALGORITHMS_ENABLED))
        {
            this.actions.add(FIPS_MODE_TLS_NULL_DIGEST_ENABLED);
            this.actions.add(FIPS_MODE_TLS_PKCS15_KEY_WRAP_ENABLED);
        }
        else
        {
            this.actions.add(name);
        }
    }

    @Override
    public boolean implies(Permission permission)
    {
        if (permission instanceof CryptoServicesPermission)
        {
            CryptoServicesPermission other = (CryptoServicesPermission)permission;

            if (this.getName().equals(other.getName()))
            {
                return true;
            }

            if (this.actions.containsAll(other.actions))
            {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj instanceof CryptoServicesPermission)
        {
            CryptoServicesPermission other = (CryptoServicesPermission)obj;

            if (this.actions.equals(other.actions))
            {
                return true;
            }
        }

        return false;
    }

    @Override
    public int hashCode()
    {
        return actions.hashCode();
    }

    @Override
    public String getActions()
    {
        return actions.toString();
    }
}
