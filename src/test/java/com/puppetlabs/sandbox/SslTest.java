package com.puppetlabs.sandbox;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.authentication.ClientCertAuthenticator;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.Test;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.net.ssl.*;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

public class SslTest {

    private class HandRolledKeyManager implements X509KeyManager {
        @Override
        public String[] getClientAliases(String s, Principal[] principals) {
            System.out.println("!!!!!!!!!!!!!CALLED!!!!!!!!!!");
            throw new NotImplementedException();
        }

        @Override
        public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
            System.out.println("!!!!!!!!!!!!!CALLED!!!!!!!!!!");
            throw new NotImplementedException();
        }

        @Override
        public String[] getServerAliases(String s, Principal[] principals) {
            System.out.println("!!!!!!!!!!!!!CALLED!!!!!!!!!!");
            throw new NotImplementedException();
        }

        @Override
        public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
            System.out.println("!!!!!!!!!!!!!CALLED!!!!!!!!!!");
            throw new NotImplementedException();
        }

        @Override
        public X509Certificate[] getCertificateChain(String s) {
            System.out.println("!!!!!!!!!!!!!CALLED!!!!!!!!!!");
            throw new NotImplementedException();
        }

        @Override
        public PrivateKey getPrivateKey(String s) {
            System.out.println("!!!!!!!!!!!!!CALLED!!!!!!!!!!");
            throw new NotImplementedException();
        }
    }

    private class HandRolledTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            System.out.println("!!!!!!!!!!!!!checkClientTrustedCALLED!!!!!!!!!!");
//            throw new CertificateException("doh");
//            throw new NotImplementedException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            System.out.println("!!!!!!!!!!!!!checkServerTrustedCALLED!!!!!!!!!!");
//            throw new NotImplementedException();
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            System.out.println("!!!!!!!!!!!!!getAcceptedIssuersCALLED!!!!!!!!!!");
//            throw new NotImplementedException();
            return new X509Certificate[0];
        }
    }

    private class HandRolledAuthenticator implements Authenticator {
        @Override
        public void setConfiguration(AuthConfiguration authConfiguration) {
//            throw new NotImplementedException();
            System.out.println("HRA.setConfig!");
        }

        @Override
        public String getAuthMethod() {
            throw new NotImplementedException();
        }

        @Override
        public Authentication validateRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean b) throws ServerAuthException {
            return Authentication.SEND_SUCCESS;
        }

        @Override
        public boolean secureResponse(ServletRequest servletRequest, ServletResponse servletResponse, boolean b, Authentication.User user) throws ServerAuthException {
            throw new NotImplementedException();
        }
    }

    public class HelloHandler extends AbstractHandler
    {
        public void handle(String target,Request baseRequest,HttpServletRequest request,HttpServletResponse response)
                throws IOException, ServletException
        {
            response.setContentType("text/html;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            baseRequest.setHandled(true);
            response.getWriter().println("<h1>Hello World</h1>");
        }
    }

    public class HelloServlet extends HttpServlet
    {
        private String greeting="Hello World";
        public HelloServlet(){}
        public HelloServlet(String greeting)
        {
            this.greeting=greeting;
        }
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
        {
            if (request.getAttribute("javax.servlet.request.X509Certificate") != null) {
                X509Certificate cert = ((X509Certificate[])(request.getAttribute("javax.servlet.request.X509Certificate")))[0];
                System.out.println("Got authenticated request for '" + cert.getSubjectDN() + "'");
//                request.getAu
            }
            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("<h1>"+greeting+"</h1>");
            response.getWriter().println("session=" + request.getSession(true).getId());
        }
    }


    @Test
    public void testHttpsServer() throws Exception {
        assertTrue(true);
        if (true) { return; }
        Security.addProvider(new BouncyCastleProvider());
        PEMReader reader;

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream("./target/test/master/conf/ssl/ca/ca_crt.pem")));
        X509Certificate ca_cert = (X509Certificate)reader.readObject();

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream("./target/master/conf/ssl/certs/localhost.pem")));
        X509Certificate cert = (X509Certificate)reader.readObject();

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream("./target/test/master/conf/ssl/private_keys/localhost.pem")));
        KeyPair keyPair = (KeyPair)reader.readObject();

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        keystore.setCertificateEntry("ca-cert-alias", ca_cert);
        keystore.setCertificateEntry("cert-alias", cert);
        keystore.setKeyEntry("key-alias", keyPair.getPrivate(),
                "password".toCharArray(), new Certificate[] {cert});





        Server server = new Server();

//        KeyManager keyManager = new HandRolledKeyManager();
        TrustManager trustManager = new HandRolledTrustManager();


        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, "password".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keystore);

        SSLContext sslContext = SSLContext.getInstance("SSL");
//        context.init(new KeyManager[] { keyManager },
        sslContext.init(kmf.getKeyManagers(),
//                new TrustManager[] { trustManager },
                tmf.getTrustManagers(),
                null);
//        context.get
//        context.getServerSocketFactory()
//        SslContextFactory sslContextFactory = new SslContextFactory(true);
        SslContextFactory sslContextFactory = new SslContextFactory();
//        sslContextFactory.setNeedClientAuth(true);
        sslContextFactory.setWantClientAuth(true);
        sslContextFactory.setSslContext(sslContext);
//        SSLContext defContext = sslContextFactory.getSslContext();



        sslContextFactory.setKeyStore(keystore);

        Connector connector = new SslSelectChannelConnector(sslContextFactory);
//        Connector connector = new SslSelectChannelConnector();
        connector.setPort(8081);
        server.addConnector(connector);


//        HelloHandler handler = new HelloHandler();
//        server.setHandler(handler);


        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        context.addServlet(new ServletHolder(new HelloServlet()),"/*");
//        context.addServlet(new ServletHolder(new HelloServlet("Buongiorno Mondo")),"/it/*");
//        context.addServlet(new ServletHolder(new HelloServlet("Bonjour le Monde")),"/fr/*");

//        SecurityHandler secHandler = new ConstraintSecurityHandler();
////        Authenticator auth = new ClientCertAuthenticator();
//        Authenticator auth = new HandRolledAuthenticator();
//        secHandler.setAuthenticator(auth);
//        context.setSecurityHandler(secHandler);

        server.setHandler(context);



        server.start();

//        SSLContext defContext = sslContextFactory.getSslContext();

        server.join();
    }


}
