package org.bouncycastle.crypto.fips;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.bouncycastle.LICENSE;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Status utility class - it has three methods on it, one for returning "isReady" status, one for a status message,
 * and one for the current module checksum.
 */
public final class FipsStatus
{
    public static final String READY = "READY";

    private static final String[] classes = new String[] { FipsAES.class.getName(), FipsTripleDES.class.getName(), FipsDH.class.getName(),
        FipsDRBG.class.getName(), FipsDSA.class.getName(), FipsEC.class.getName(),
        FipsKDF.class.getName(), FipsPBKD.class.getName(), FipsRSA.class.getName(), FipsSHS.class.getName() };

    private static volatile Loader loader;
    private static volatile Throwable statusException;

    private FipsStatus()
    {

    }

    /**
     * Check to see if the FIPS module is ready for operation.
     *
     * @return true if the module is ready for operation with all self-tests complete.
     */
    public static boolean isReady()
    {
        // FSM_STATE:2.0, "POWER ON INITIALIZATION", "Initialization of the module after power on or RST"
        synchronized (READY)
        {
            if (loader == null && statusException == null)
            {
                try
                {
                    loader = new Loader();
                }
                catch (Exception e)
                {
                    statusException = e;

                    moveToErrorStatus(new FipsOperationError("Module startup failed: " + e.getMessage(), e));
                }

                // FSM_STATE:3.1, "FIRMWARE INTEGRITY - HMAC-SHA256", "The module is performing the Firmware Integrity Check: HMAC-SHA256"
                // FSM_TRANS:3.3
                checksumValidate();
                // FSM_TRANS:3.4
            }
            else if (statusException != null)
            {
                throw new FipsOperationError("Module in error status: " + statusException.getMessage(), statusException);
            }
        }

        // FSM_TRANS:3.1
        return true;
    }

    private static void checksumValidate()
    {
        JarFile jarFile = AccessController.doPrivileged(new PrivilegedAction<JarFile>()
                        {
                            public JarFile run()
                            {
                                return getJarFile();
                            }
                        });

        if (jarFile != null)      // we only do the checksum calculation if we are running off a jar file.
        {
            try
            {
                byte[] hmac = calculateModuleHMAC(jarFile);
                InputStream macIn = jarFile.getInputStream(jarFile.getEntry("META-INF/HMAC.SHA256"));

                StringBuilder sb = new StringBuilder(hmac.length * 2);

                int ch;
                while ((ch = macIn.read()) >= 0 && ch != '\r' && ch != '\n')
                {
                    sb.append((char)ch);
                }

                byte[] fileMac = Hex.decode(sb.toString().trim());

                if (!Arrays.areEqual(hmac, fileMac))
                {
                    moveToErrorStatus(new FipsOperationError("Module checksum failed: expected [" + sb.toString().trim() + "] got [" + Strings.fromByteArray(Hex.encode(hmac))) + "]");
                }
            }
            catch (Exception e)
            {
                statusException = e;

                moveToErrorStatus(new FipsOperationError("Module checksum failed: " + e.getMessage(), e));
            }
        }
    }

    /**
     * Return a message indicating the current status.
     *
     * @return  READY if all is well, an exception message otherwise.
     */
    public static String getStatusMessage()
    {
        try
        {
            FipsStatus.isReady();
        }
        catch (FipsOperationError e)
        {
            // ignore as loader exception will now be set.
        }

        if (statusException != null)
        {
            return statusException.getMessage();
        }

        return READY;
    }

    private static void loadClass(String className)
    {
        try
        {
            Class.forName(className);
        }
        catch (ExceptionInInitializerError e)
        {
            if (e.getCause() != null)
            {
                statusException = e.getCause();
            }
            else
            {
                statusException = e;
            }
            throw e;
        }
        catch (ClassNotFoundException e)
        {
            statusException = e;
            throw new IllegalStateException("Unable to initialize module: " + e.getMessage(), e);
        }
    }

    /**
     * Return the HMAC used to verify that the code contained in the module is the same
     *
     * @return the internally calculated HMAC for the module.
     */
    public static byte[] getModuleHMAC()
    {
        try
        {
            return calculateModuleHMAC(getJarFile());
        }
        catch (Exception e)
        {
            return new byte[32];
        }
    }

    private static byte[] calculateModuleHMAC(JarFile jarFile)
    {
        // this code is largely the standard approach to self verifying a JCE with some minor modifications. It will calculate
        // the SHA-256 HMAC on the classes.
        try
        {
            HMac hMac = new HMac(new SHA256Digest());

            hMac.init(new KeyParameterImpl(Strings.toByteArray(CryptoServicesRegistrar.MODULE_HMAC_KEY)));

            // build an index to make sure we get things in the same order.
            Map<String, JarEntry> index = new TreeMap<String, JarEntry>();

            for (Enumeration<JarEntry> entries = jarFile.entries(); entries.hasMoreElements();)
            {
                JarEntry jarEntry = entries.nextElement();

                // Skip directories and META-INF.
                if (jarEntry.isDirectory() || jarEntry.getName().startsWith("META-INF/"))
                {
                    continue;
                }

                Object last = index.put(jarEntry.getName(), jarEntry);
                if (last != null)
                {
                    IllegalStateException e =  new IllegalStateException("Unable to initialize module: duplicate entry found in jar file");
                    statusException = e;
                    throw e;
                }
            }

            byte[] buf = new byte[8192];
            for (String name : index.keySet())
            {
                JarEntry jarEntry = index.get(name);
                InputStream is = jarFile.getInputStream(jarEntry);

                // Read in each jar entry. A SecurityException will
                // be thrown if a signature/digest check fails - if that happens
                // we'll just return an empty checksum

                // header information
                byte[] encName = Strings.toUTF8ByteArray(jarEntry.getName());
                hMac.update((byte)0x5B);   // '['
                hMac.update(encName, 0, encName.length);
                hMac.update(Pack.longToBigEndian(jarEntry.getSize()), 0, 8);
                hMac.update((byte)0x5D);    // ']'

                // contents
                int n;
                while ((n = is.read(buf, 0, buf.length)) != -1)
                {
                    hMac.update(buf, 0, n);
                }
                is.close();
            }

            hMac.update((byte)0x5B);   // '['
            byte[] encName = Strings.toUTF8ByteArray("END");
            hMac.update(encName, 0, encName.length);
            hMac.update((byte)0x5D);    // ']'

            byte[] hmacResult = new byte[hMac.getMacSize()];

            hMac.doFinal(hmacResult, 0);

            return hmacResult;
        }
        catch (Exception e)
        {
            return new byte[32];
        }
    }

    private static JarFile getJarFile()
    {
        // we use the MARKER file, at the same level in the class hierarchy as this
        // class, to find the enclosing Jar file (if one exists)

        JarFile result = null;

        final String markerName = LICENSE.class.getCanonicalName().replace(".", "/").replace("LICENSE", "MARKER");
        final String marker = getMarker(LICENSE.class, markerName);

        if (marker != null && marker.startsWith("jar:file:") && marker.contains("!/"))
        {
            try
            {
                String jarFilename = URLDecoder.decode(marker.substring("jar:file:".length(), marker.lastIndexOf("!/")), "UTF-8");

                result = new JarFile(jarFilename);
            }
            catch (IOException e)
            {
                // we found our jar file, but couldn't open it
                result = null;
            }
        }

        return result;
    }
    
    static void moveToErrorStatus(String error)
    {
        moveToErrorStatus(new FipsOperationError(error));
    }

    static void moveToErrorStatus(FipsOperationError error)
    {
        // FSM_STATE:8.0
        // FSM_TRANS:3.2
        statusException =  error;
        throw (FipsOperationError)statusException;
    }

    /**
     * Return true if the module is in error status, false otherwise.
     *
     * @return true if an error has been detected, false otherwise.
     */
    public static boolean isErrorStatus()
    {
        return statusException != null;
    }

    static class Loader
    {
        Loader()
            throws Exception
        {
            // FSM_STATE:3.0, "POWER ON SELF-TEST", ""
            for (String cls : classes)
            {
                if (!isErrorStatus())
                {
                    loadClass(cls);
                }
            }
        }
    }

    static String getMarker(Class sourceClass, final String markerName)
    {
        ClassLoader loader = sourceClass.getClassLoader();

        if (loader != null)
        {
            return loader.getResource(markerName).toString();
        }
        else
        {
            return AccessController.doPrivileged(new PrivilegedAction<String>()
            {
                public String run()
                {
                    return ClassLoader.getSystemResource(markerName).toString();
                }
            });
        }
    }
}
