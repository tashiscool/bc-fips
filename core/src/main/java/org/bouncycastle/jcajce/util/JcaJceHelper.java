/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.jcajce.util;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

/**
 * Base interface for the helper classes for working with the JCA/JCE conform to.
 */
public interface JcaJceHelper
{
    Cipher createCipher(
        String algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException;

    Mac createMac(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyAgreement createKeyAgreement(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyGenerator createKeyGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyFactory createKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    SecretKeyFactory createSecretKeyFactory(String algorithm)
           throws NoSuchAlgorithmException, NoSuchProviderException;

    KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    MessageDigest createDigest(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    Signature createSignature(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;

    CertificateFactory createCertificateFactory(String algorithm)
        throws NoSuchProviderException, CertificateException;

    SecureRandom createSecureRandom(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException;
}
