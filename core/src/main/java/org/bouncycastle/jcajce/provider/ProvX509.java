package org.bouncycastle.jcajce.provider;

/**
 * For some reason the class path project thinks that such a KeyFactory will exist.
 */
class ProvX509
    extends AsymmetricAlgorithmProvider
{
    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new X509KeyFactory(provider);
            }
        });
        provider.addAlias("Alg.Alias.KeyFactory.X509", "X.509");

        //
        // certificate factories.
        //
        provider.addAlgorithmImplementation("CertificateFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new CertificateFactory(provider);
            }
        });
        provider.addAlias("Alg.Alias.CertificateFactory.X509", "X.509");
    }
}
