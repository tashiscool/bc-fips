package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.general.GOST28147;

/**
 * A parameter spec generating parameters for GOST-28147.
 */
public class GOST28147GenParameterSpec
    implements AlgorithmParameterSpec
{
    private final String sBoxName;

    public GOST28147GenParameterSpec(
        String sBoxName)
    {
        this.sBoxName = sBoxName;
    }

    public GOST28147GenParameterSpec(
        ASN1ObjectIdentifier sBoxOID)
    {
        this.sBoxName = GOST28147.getSBoxName(sBoxOID);
    }

    public String getSBoxName()
    {
        return sBoxName;
    }
}