package com.puppetlabs.sandbox;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.Test;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Random;

import static org.junit.Assert.fail;

public class SslTest {

    private static final String PATH_CA_PASSWORD = "./target/test/master/conf/ssl/ca/private/ca.pass";
    private static final String PATH_CA_CERT = "./target/test/master/conf/ssl/ca/ca_crt.pem";
    // TODO: don't hard-code localhost
    private static final String PATH_MASTER_CERT = "./target/master/conf/ssl/certs/localhost.pem";
    private static final String PATH_MASTER_PRIVATE_KEY = "./target/test/master/conf/ssl/private_keys/localhost.pem";
    private static final String PATH_MASTER_PUBLIC_KEY = "./target/test/master/conf/ssl/public_keys/localhost.pem";

    public class HelloServlet extends HttpServlet
    {
        private String greeting="Hello World";
        public HelloServlet(){}

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
        Security.addProvider(new BouncyCastleProvider());

        if (! masterCertsExist()) {
            createMasterCerts();
        }

        KeyStore keystore = createMasterKeyStore();


        Server server = new Server();

//        KeyManager keyManager = new HandRolledKeyManager();
//        TrustManager trustManager = new HandRolledTrustManager();


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


    private boolean masterCertsExist() {
        return (new File(PATH_CA_CERT).exists() &&
                new File(PATH_MASTER_CERT).exists() &&
                new File(PATH_MASTER_PRIVATE_KEY).exists());
    }


    private void createMasterCerts() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException {
        FileUtils.forceMkdir(new File(PATH_CA_PASSWORD).getParentFile());
        FileUtils.forceMkdir(new File(PATH_MASTER_PRIVATE_KEY).getParentFile());
        FileUtils.forceMkdir(new File(PATH_MASTER_PUBLIC_KEY).getParentFile());

        saveCAPassword(generateCAPassword());
        KeyPair keyPair = generateKeyPair();
        saveKeyPair(keyPair);

        // TODO: don't hard-code localhost
        PKCS10CertificationRequest certReq = generateCertReq(keyPair, "Puppet CA: localhost");
        X509Certificate cert = signCertificateRequest(certReq, keyPair.getPrivate());
        saveCACert(cert);

//        # Create a new cert request.  We do this specially, because we don't want
//        # to actually save the request anywhere.
//        request = Puppet::SSL::CertificateRequest.new(host.name)
//
//        # We deliberately do not put any subjectAltName in here: the CA
//        # certificate absolutely does not need them. --daniel 2011-10-13
//        request.generate(host.key)
//
//        # Create a self-signed certificate.
//        @certificate = sign(host.name, false, request)
//
//        # And make sure we initialize our CRL.
//                crl
        fail();
    }

    private String generateCAPassword() {
        StringBuilder sb = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i < 20; i++) {
            sb.append((char)(rand.nextInt(74) + 48));
        }
        return sb.toString();
    }

    private void saveCAPassword(String caPass) throws IOException {
        FileUtils.writeStringToFile(new File(PATH_CA_PASSWORD), caPass, "UTF-8");
    }

    private KeyPair generateKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(4096);
        KeyPair keyPair = keyGen.generateKeyPair();

        return keyPair;
    }

    private void saveKeyPair(KeyPair keyPair) throws IOException {
        PEMWriter pemWriter = new PEMWriter(new FileWriter(PATH_MASTER_PRIVATE_KEY));
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();

        pemWriter = new PEMWriter(new FileWriter(PATH_MASTER_PUBLIC_KEY));
        pemWriter.writeObject(keyPair.getPublic());
        pemWriter.flush();
    }


    private PKCS10CertificationRequest generateCertReq(KeyPair keyPair, String commonName) throws OperatorCreationException, IOException {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.CN, commonName);

        X500Name x500Name = x500NameBuilder.build();

        // TODO: the puppet code sets a property "version=0" on the request object
        //  here; can't figure out how to do that at the moment.
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(x500Name, keyPair.getPublic());

        // TODO: support DNS ALT names; probably looks something like this:
//        Extensions extensions = new Extensions(new Extension[] {
//                new Extension(X509Extension.subjectAlternativeName, false,
//                        new DEROctetString(
//                                new GeneralNames(new GeneralName[] {
//                                        new GeneralName(GeneralName.dNSName, "foo.bar.com"),
//                                        new GeneralName(GeneralName.dNSName, "bar.baz.com"),
//                                        })))
//        });
//
//        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
//                new DERSet(extensions));

        PKCS10CertificationRequest request = requestBuilder.build(
                new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate()));

        return request;
    }

    private X509Certificate signCertificateRequest(PKCS10CertificationRequest certReq, PrivateKey privateKey) {
        throw new NotImplementedException();
    }

    private void saveCACert(X509Certificate cert) {
        throw new NotImplementedException();
    }


    private KeyStore createMasterKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        PEMReader reader;

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream(PATH_CA_CERT)));
        X509Certificate ca_cert = (X509Certificate)reader.readObject();

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream(PATH_MASTER_CERT)));
        X509Certificate cert = (X509Certificate)reader.readObject();

        reader = new PEMReader(new InputStreamReader(
                new FileInputStream(PATH_MASTER_PRIVATE_KEY)));
        KeyPair keyPair = (KeyPair)reader.readObject();

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        keystore.setCertificateEntry("ca-cert-alias", ca_cert);
        keystore.setCertificateEntry("cert-alias", cert);
        keystore.setKeyEntry("key-alias", keyPair.getPrivate(),
                "password".toCharArray(), new Certificate[] {cert});
        return keystore;
    }


}
