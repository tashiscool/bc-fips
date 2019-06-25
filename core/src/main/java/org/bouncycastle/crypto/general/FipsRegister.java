package org.bouncycastle.crypto.general;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsEngineProvider;
import org.bouncycastle.crypto.internal.EngineProvider;

/**
 * Local register that provides access to engines for FIPS algorithms for use with general/non-FIPS-approved modes of use.
 */
public final class FipsRegister
{
    FipsRegister()
    {

    }

    private static final Map<FipsAlgorithm, EngineProvider> providerMap = new HashMap<FipsAlgorithm, EngineProvider>();

    public static void registerEngineProvider(FipsAlgorithm algorithm, FipsEngineProvider provider)
    {
        if (algorithm == null || provider == null)
        {
            throw new IllegalArgumentException("Arguments cannot be null");
        }

        providerMap.put(algorithm, provider);
    }

    static <T> EngineProvider<T> getProvider(FipsAlgorithm algorithm)
    {
        return providerMap.get(algorithm);
    }
}
