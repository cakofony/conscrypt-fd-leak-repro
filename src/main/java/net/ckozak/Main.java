package net.ckozak;

import io.undertow.Undertow;
import io.undertow.server.handlers.ResponseCodeHandler;
import org.conscrypt.Conscrypt;
import org.xnio.Options;
import org.xnio.Sequence;
import org.xnio.SslClientAuthMode;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Provider conscryptProvider = Conscrypt.newProvider();
        Security.addProvider(conscryptProvider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream fis1 = new FileInputStream("server.keystore")) {
            ks.load(fis1, "password".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "password".toCharArray());
        KeyManager[] keyManagers = kmf.getKeyManagers();

        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream fis = new FileInputStream("server.truststore")) {
            ts.load(fis, null);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] trustManagers = tmf.getTrustManagers();
        SSLContext conscryptContext = SSLContext.getInstance("TLSv1.2", conscryptProvider.getName());
        conscryptContext.init(keyManagers, trustManagers, null);

        Undertow server = Undertow.builder()
                .addHttpsListener(4443, null, conscryptContext)
                .setHandler(ResponseCodeHandler.HANDLE_200)
                .setSocketOption(Options.SSL_CLIENT_AUTH_MODE, SslClientAuthMode.NOT_REQUESTED)
                .setSocketOption(Options.SSL_ENABLED_CIPHER_SUITES, Sequence.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
                .setSocketOption(Options.SSL_ENABLED_PROTOCOLS, Sequence.of("TLSv1.2"))
                .build();
        server.start();
        String hostname = InetAddress.getLocalHost().getHostName();
        new ProcessBuilder()
                .command(("ab -v -I -c 10 -n 100000 https://" + hostname + ":4443/ping").split("\\s"))
                .inheritIO()
                .start();
    }
}
