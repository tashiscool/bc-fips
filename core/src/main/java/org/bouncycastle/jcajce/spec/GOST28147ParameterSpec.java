package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.general.GOST28147;
import org.bouncycastle.util.Arrays;

/**
 * A parameter spec for the GOST-28147 cipher.
 */
public class GOST28147ParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] iv;
    private final byte[] sBox;

    public GOST28147ParameterSpec(
        byte[] sBox)
    {
        this(sBox, null);
    }

    public GOST28147ParameterSpec(
        byte[] sBox,
        byte[] iv)
    {
        this.sBox = Arrays.clone(sBox);
        this.iv = Arrays.clone(iv);
    }
    
    public GOST28147ParameterSpec(
        String sBoxName)
    {
        this(sBoxName, null);
    }

    public GOST28147ParameterSpec(
        String sBoxName,
        byte[] iv)
    {
        this.sBox = GOST28147.getSBox(sBoxName);
        this.iv = Arrays.clone(iv);
    }

    public GOST28147ParameterSpec(
        ASN1ObjectIdentifier sBoxOID,
        byte[] iv)
    {
        this.sBox = GOST28147.getSBox(sBoxOID);
        this.iv = Arrays.clone(iv);
    }

    public byte[] getSBox()
    {
        return Arrays.clone(sBox);
    }

    /**
     * Returns the IV or null if this parameter set does not contain an IV.
     *
     * @return the IV or null if this parameter set does not contain an IV.
     */
    public byte[] getIV()
    {
        return Arrays.clone(iv);
    }
}