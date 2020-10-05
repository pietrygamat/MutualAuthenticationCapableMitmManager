package proxy.auth;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import proxy.auth.MutualAuthenticationCapableMitmManager.KeyManagerFactoryProvider;

import javax.net.ssl.KeyManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class KeyManagerFactoryProviders {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Uses a .p12 file to create a KeyManagerFactory e.g. for server facing SSLContext of Man-In-The-Middle proxy,
     * providing client authorization.
     * @param certFile PKCS12 (.p12) file
     * @param password used to open the certFile
     */
    static KeyManagerFactoryProvider usingPKCS12File(File certFile, char[] password) {
        return new PKCS12BasedKeyManagerProvider(certFile, password);
    }

    /**
     * Uses a PEM key and certificate files to create KeyManagerFactory for SSLContext e.g. to impersonate specific
     * server to the client of Man-In-The-Middle proxy
     *
     * @param certFile certificate file in PEM format
     * @param keyFile  key file in PEM format
     */
    static KeyManagerFactoryProvider usingPemKeyPair(File certFile, File keyFile) {
        return new PEMKeyPairBasedKeyManagerProvider(certFile, keyFile);
    }

    private static class PKCS12BasedKeyManagerProvider implements KeyManagerFactoryProvider {
        private final File keyStoreFile;
        private final char[] keyStorePassword;

        PKCS12BasedKeyManagerProvider(File keyStoreFile, char[] keyStorePassword) {
            this.keyStoreFile = keyStoreFile;
            this.keyStorePassword = keyStorePassword;
        }

        @Override
        public KeyManagerFactory create() {
            try {
                final KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(keyStoreFile), keyStorePassword);
                final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, keyStorePassword);
                return kmf;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
                throw new IllegalStateException("Could not create KeyManagerFactory", e);
            }
        }
    }

    private static class PEMKeyPairBasedKeyManagerProvider implements KeyManagerFactoryProvider {
        private final File keyPEMFile;
        private final File certPEMFile;

        private final static char[] DEFAULT_PASSWORD = "123456".toCharArray();

        PEMKeyPairBasedKeyManagerProvider(File certPEMFile, File keyPEMFile) {
            this.certPEMFile = certPEMFile;
            this.keyPEMFile = keyPEMFile;
        }

        @Override
        public KeyManagerFactory create() {
            KeyStore keyStore;
            X509Certificate certificate;
            Key key;

            try (FileReader keyFileReader = new FileReader(keyPEMFile)) {
                PEMParser pp = new PEMParser(keyFileReader);
                PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
                KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
                key = kp.getPrivate();
            } catch (IOException e) {
                throw new IllegalStateException("Could not read from file", e);
            }

            try (FileReader certFileReader = new FileReader(certPEMFile)) {
                PEMParser pp = new PEMParser(certFileReader);
                X509CertificateHolder certHolder = (X509CertificateHolder) pp.readObject();
                certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
            } catch (IOException | CertificateException e) {
                throw new IllegalStateException("Could not read from file", e);
            }

            try {
                keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null);
                keyStore.setKeyEntry(
                        certificate.getSubjectDN().getName(), key,
                        DEFAULT_PASSWORD, new Certificate[]{certificate});

                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keyStore, DEFAULT_PASSWORD);
                return kmf;
            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new IllegalStateException("Could not crate Key Store", e);
            } catch (IOException e) {
                throw new IllegalStateException("Could not write to file", e);
            }
        }
    }
}
