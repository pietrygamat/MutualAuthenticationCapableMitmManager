package proxy.auth;

import io.netty.handler.codec.http.HttpRequest;
import org.littleshoot.proxy.MitmManager;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class MutualAuthenticationCapableMitmManager implements MitmManager {
    public interface KeyManagerFactoryProvider {
        KeyManagerFactory create();
    }

    private final SSLContext serverSideSSLContext;
    private final SSLContext clientSideSSLContext;

    MutualAuthenticationCapableMitmManager(KeyManagerFactoryProvider serverFacingKMF,
                                           KeyManagerFactoryProvider clientFacingKMF) {
        serverSideSSLContext = getSSLContext(serverFacingKMF.create());
        clientSideSSLContext = getSSLContext(clientFacingKMF.create());
    }

    @Override
    public SSLEngine serverSslEngine(String peerHost, int peerPort) {
        return serverSideSSLContext.createSSLEngine(peerHost, peerPort);
    }

    @Override
    public SSLEngine serverSslEngine() {
        return serverSideSSLContext.createSSLEngine();
    }

    @Override
    public SSLEngine clientSslEngineFor(HttpRequest httpRequest, SSLSession sslSession) {
        return clientSideSSLContext.createSSLEngine();
    }

    private synchronized SSLContext getSSLContext(KeyManagerFactory kmf) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManager[] trustManagers = getTrustManagers();
            sslContext.init(kmf.getKeyManagers(), trustManagers, null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Error setting SSL facing server", e);
        }
    }

    private TrustManager[] getTrustManagers() {
        return new TrustManager[]{
                // TrustManager that trusts all servers
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] arg0, String arg1) {
                        // always trust
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] arg0, String arg1) {
                        // always trust
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                }};
    }
}
