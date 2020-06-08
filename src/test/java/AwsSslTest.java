import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class AwsSslTest {

    @BeforeEach
    void setUp() {
        // run with an added -Djava.security.debug=certpath
        System.setProperty("javax.net.debug", "all");

        // https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-E1A3A7C3-309A-4415-903B-B31C96F68C86
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        Security.setProperty("ocsp.enable", "true");
    }

    @Test
    void valid() throws IOException {
        get("https://good.sca1a.amazontrust.com/", urlConnection -> {
            try {
                assertThat(urlConnection.getResponseCode()).isEqualTo(200);
                Certificate[] serverCertificates = urlConnection.getServerCertificates();
                assertThat(serverCertificates[2]).isInstanceOf(X509Certificate.class);
                X509Certificate awsCertificate = (X509Certificate) serverCertificates[2];
                assertThat(awsCertificate.getIssuerDN().getName()).isEqualTo("CN=Amazon Root CA 1, O=Amazon, C=US");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void expired() throws IOException {
        get("https://expired.sca1a.amazontrust.com/", urlConnection -> {
            assertThatExceptionOfType(SSLHandshakeException.class)
                    .isThrownBy(urlConnection::getResponseCode)
                    .withRootCauseInstanceOf(CertificateExpiredException.class);
        });
    }

    @Test
    void revoked() throws IOException {
        get("https://revoked.sca1a.amazontrust.com/", urlConnection -> {
            assertThatExceptionOfType(SSLHandshakeException.class)
                    .isThrownBy(urlConnection::getResponseCode)
                    .withRootCauseInstanceOf(CertificateRevokedException.class);
        });
    }

    private void get(String urlString, Consumer<HttpsURLConnection> consumer) throws IOException {
        URL url = new URL(urlString);
        HttpsURLConnection urlConnection = null;
        try {
            urlConnection = (HttpsURLConnection) url.openConnection();
            urlConnection.setRequestMethod("GET");
            consumer.accept(urlConnection);
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }
}