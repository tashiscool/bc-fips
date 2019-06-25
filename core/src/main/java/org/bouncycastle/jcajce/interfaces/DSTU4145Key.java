package org.bouncycastle.jcajce.interfaces;

import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;

/**
 * Main interface for a DSTU-4145 key.
 */
public interface DSTU4145Key
{
    DSTU4145ParameterSpec getParams();
}
