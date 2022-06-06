package proxy.auth;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.littleshoot.proxy.HttpProxyServer;
import org.openqa.selenium.By;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.DEFINED_PORT;
import static proxy.auth.KeyManagerFactoryProviders.usingPKCS12File;
import static proxy.auth.KeyManagerFactoryProviders.usingPemKeyPair;

@SpringBootTest(webEnvironment = DEFINED_PORT, classes = ExampleWebServer.class)
public class MutualAuthenticationTest {

    // server certificate and private key extracted from keystore.example.com.p12
    static final File serverCertFile = new File("src/test/resources/server.example.com.cer");
    static final File serverKeyFile = new File("src/test/resources/server.example.com.key");

    // client certificate and private key extracted from keystore.example.com.p12
    static final File clientCertFile = new File("src/test/resources/client.example.com.p12");
    static final String clientCertPassword = "changeit";

    // Test webserver started locally for this test
    static final String webserverUrl = "https://localhost:9443";

    static final int proxyPort = 5555;
    static HttpProxyServer proxyServer;
    WebDriver driver;

    @BeforeAll
    public static void startProxy() {
        proxyServer = org.littleshoot.proxy.impl.DefaultHttpProxyServer.bootstrap()
                .withName(clientCertFile.getName())
                .withPort(proxyPort) // or 0 for a random port
                .withManInTheMiddle(new MutualAuthenticationCapableMitmManager(
                        usingPKCS12File(clientCertFile, clientCertPassword.toCharArray()),
                        usingPemKeyPair(serverCertFile, serverKeyFile)))
                .start();
    }

    @Test
    public void testWithChrome() {
        org.openqa.selenium.Proxy proxy = new Proxy();
        proxy.setSslProxy("localhost:" + proxyPort);

        // overwrite the default no-proxy for localhost, 127.0.0.1
        proxy.setNoProxy("<-loopback>");

        ChromeOptions options = new ChromeOptions();
        options.setProxy(proxy);
        // Only required if server certificate is not issued by a generally known CA
        // Not related to the use of MitM proxy
        options.setAcceptInsecureCerts(true);

        WebDriverManager.chromedriver().setup();
        driver = WebDriverManager.chromedriver().capabilities(options).create();
        driver.get(webserverUrl);
        Assertions.assertEquals("Hello", driver.findElement(By.id("header")).getText());
    }

    @Test
    public void testWithFirefox() {
        org.openqa.selenium.Proxy proxy = new Proxy();
        proxy.setSslProxy("localhost:" + proxyPort);

        // overwrite the default no-proxy for localhost
        // do not proxy browser telemetry to avoid unrelated SSL errors
        proxy.setNoProxy("<-loopback>,*.mozilla.com,*.mozilla.net");

        FirefoxOptions options = new FirefoxOptions();
        options.setProxy(proxy);

        // again, overwrite the default no-proxy for localhost in a Firefox specific way
        options.addPreference("network.proxy.allow_hijacking_localhost", true);

        // Only required if server certificate is not issued by a generally known CA
        // Not related to the use of MitM proxy
        options.setAcceptInsecureCerts(true);

        WebDriverManager.firefoxdriver().setup();
        driver = WebDriverManager.firefoxdriver().capabilities(options).create();
        driver.get(webserverUrl);
        Assertions.assertEquals("Hello", driver.findElement(By.id("header")).getText());
    }


    @AfterEach
    void tearDown() {
        driver.quit();
    }

    @AfterAll
    static void stopProxy() {
        proxyServer.stop();
    }
}
