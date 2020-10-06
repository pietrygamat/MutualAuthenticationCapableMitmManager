Mutual Authentication is Selenium
---

A simple code that uses LittleProxy as a Man-In-The-Middle proxy to be used by e.g. Selenium to connect to servers that
require client side certificate, working around the problem of WebDriver not exposing any APIs to select one. To use it, 
create a proxy server, feed it a client certificate the server accepts and a server certificate the client trusts, then
configure WebDriver instance to use it.

    File clientCertFile = ...;        // client cert as .p12
    char[] clientCertPassword = ...;  // key password 
    File serverCertFile = ...;        // PEM file
    File serverKeyFile = ...;         // PEM file

    org.littleshoot.proxy.impl.DefaultHttpProxyServer.bootstrap()
			.withName(clientCertFile.getName())
			.withPort(5555)
			.withAllowLocalOnly(true)
			.withManInTheMiddle(new MutualAuthenticationCapableMitmManager(
					usingPKCS12File(clientCertFile, clientCertPassword), 
					usingPemKeyPair(serverCertFile, serverKeyFile)))
			.start();

    org.openqa.selenium.Proxy proxy = new Proxy();
    proxy.setSslProxy("127.0.0.1:5555");
    proxy.setNoProxy("<-loopback>"); // overwrite the default no-proxy for localhost, 127.0.0.1
    
    FirefoxOptions options = new FirefoxOptions();
    options.setProxy(proxy);
    WebDriver driver = new FirefoxDriver(options);

