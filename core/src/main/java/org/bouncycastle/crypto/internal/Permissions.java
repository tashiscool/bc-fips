package org.bouncycastle.crypto.internal;

import java.security.Permission;

import org.bouncycastle.crypto.CryptoServicesPermission;

public class Permissions
{
    public static final Permission CanOutputPrivateKey = new CryptoServicesPermission(CryptoServicesPermission.FIPS_MODE_EXPORT_PRIVATE_KEY);
    public static final Permission CanOutputSecretKey = new CryptoServicesPermission(CryptoServicesPermission.FIPS_MODE_EXPORT_SECRET_KEY);

    public static final Permission TlsNullDigestEnabled = new CryptoServicesPermission(CryptoServicesPermission.FIPS_MODE_TLS_NULL_DIGEST_ENABLED);
    public static final Permission TlsPKCS15KeyWrapEnabled = new CryptoServicesPermission(CryptoServicesPermission.FIPS_MODE_TLS_PKCS15_KEY_WRAP_ENABLED);
}
