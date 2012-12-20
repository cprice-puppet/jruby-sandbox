package com.puppetlabs.sandbox;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
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
import org.joda.time.DateTime;
import org.joda.time.Period;
import org.junit.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;

public class SslTest {

    private static final String PATH_TEST_DIR = "./target/test/master/conf/ssl";
//    private static final String PATH_CA_PASSWORD = "./target/test/master/conf/ssl/ca/private/ca.pass";
    private static final String PATH_CA_PUBLIC_KEY = PATH_TEST_DIR + "/ca/ca_pub.pem";
    private static final String PATH_CA_PRIVATE_KEY = PATH_TEST_DIR + "/ca/ca_key.pem";
    private static final String PATH_CA_CERT = PATH_TEST_DIR + "/ca/ca_crt.pem";
    // TODO: don't hard-code localhost
    private static final String PATH_MASTER_PUBLIC_KEY = PATH_TEST_DIR + "/public_keys/localhost.pem";
    private static final String PATH_MASTER_PRIVATE_KEY = PATH_TEST_DIR + "/private_keys/localhost.pem";
    private static final String PATH_MASTER_CERT = PATH_TEST_DIR + "/certs/localhost.pem";

    private static final AtomicInteger nextSerialNum = new AtomicInteger(1);

    public class HelloServlet extends HttpServlet
    {
        private String greeting="Hello World";
        public HelloServlet(){}

        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
        {
            if (request.getAttribute("javax.servlet.request.X509Certificate") != null) {
                X509Certificate cert = ((X509Certificate[])(request.getAttribute("javax.servlet.request.X509Certificate")))[0];
                System.out.println("Got authenticated request for '" + cert.getSubjectDN() + "'");
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

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, "password".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keystore);

        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(kmf.getKeyManagers(),
                tmf.getTrustManagers(),
                null);
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setWantClientAuth(true);
        sslContextFactory.setSslContext(sslContext);

        sslContextFactory.setKeyStore(keystore);

        Connector connector = new SslSelectChannelConnector(sslContextFactory);
        connector.setPort(8140);
        server.addConnector(connector);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        context.addServlet(new ServletHolder(new HelloServlet()),"/*");
//        context.addServlet(new ServletHolder(new HelloServlet("Buongiorno Mondo")),"/it/*");
//        context.addServlet(new ServletHolder(new HelloServlet("Bonjour le Monde")),"/fr/*");

        server.setHandler(context);

        server.start();
        server.join();
    }


    private boolean masterCertsExist() {
        return (new File(PATH_CA_CERT).exists() &&
                new File(PATH_MASTER_CERT).exists() &&
                new File(PATH_MASTER_PRIVATE_KEY).exists());
    }


    private void createMasterCerts() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException {
        for (String filePath : new String[] {
                PATH_CA_CERT, PATH_CA_PRIVATE_KEY, PATH_CA_PUBLIC_KEY,
                PATH_MASTER_CERT, PATH_MASTER_PRIVATE_KEY, PATH_MASTER_PUBLIC_KEY
        }) {
            FileUtils.forceMkdir(new File(filePath).getParentFile());
        }

        // TODO: it doesn't look like the CA password file is ever actually
        // used for anything in Puppet.
//        saveCAPassword(generateCAPassword());

        KeyPair caKeyPair = generateKeyPair();
        saveToPEM(caKeyPair.getPublic(), PATH_CA_PUBLIC_KEY);
        saveToPEM(caKeyPair.getPrivate(), PATH_CA_PRIVATE_KEY);

        // TODO: don't hard-code localhost
        String host = "localhost";

        X500Name caName = generateX500Name("Puppet CA: " + host);

        PKCS10CertificationRequest caCertReq = generateCertReq(caKeyPair, caName);
        X509Certificate caCert = signCertificateRequest(caCertReq, caName, caKeyPair.getPrivate());
        saveToPEM(caCert, PATH_CA_CERT);

        KeyPair hostKeyPair = generateKeyPair();
        saveToPEM(hostKeyPair.getPublic(), PATH_MASTER_PUBLIC_KEY);
        saveToPEM(hostKeyPair.getPrivate(), PATH_MASTER_PRIVATE_KEY);

        X500Name hostName = generateX500Name(host);

        PKCS10CertificationRequest hostCertReq = generateCertReq(hostKeyPair, hostName);
        X509Certificate hostCert = signCertificateRequest(hostCertReq, caName, caKeyPair.getPrivate());
        saveToPEM(hostCert, PATH_MASTER_CERT);

        // TODO: crl
//        # And make sure we initialize our CRL.
//                crl
    }

    // TODO: It really sucks that the most specific type we can use
    //  here is 'Object'.
    private void saveToPEM(Object pemObject, String filePath) throws IOException {
        PEMWriter pemWriter = new PEMWriter(new FileWriter(filePath));
        pemWriter.writeObject(pemObject);
        pemWriter.flush();
    }


//    private String generateCAPassword() {
//        StringBuilder sb = new StringBuilder();
//        Random rand = new Random();
//        for (int i = 0; i < 20; i++) {
//            sb.append((char)(rand.nextInt(74) + 48));
//        }
//        return sb.toString();
//    }
//
//    private void saveCAPassword(String caPass) throws IOException {
//        FileUtils.writeStringToFile(new File(PATH_CA_PASSWORD), caPass, "UTF-8");
//    }

    private KeyPair generateKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(4096);
        KeyPair keyPair = keyGen.generateKeyPair();

        return keyPair;
    }

    private X500Name generateX500Name(String commonName) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.CN, commonName);

        return x500NameBuilder.build();
    }

    private PKCS10CertificationRequest generateCertReq(KeyPair keyPair, X500Name subjectName) throws OperatorCreationException, IOException {
        // TODO: the puppet code sets a property "version=0" on the request object
        //  here; can't figure out how to do that at the moment.  Not sure if it's needed.
        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(subjectName, keyPair.getPublic());

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


    private X509Certificate signCertificateRequest(PKCS10CertificationRequest certReq,
                                                   X500Name issuer,
                                                   PrivateKey issuerPrivateKey)
            throws OperatorCreationException, CertificateException {

//        # Make the certificate valid as of yesterday, because so many people's
//        # clocks are out of sync.  This gives one more day of validity than people
//        # might expect, but is better than making every person who has a messed up
//        # clock fail, and better than having every cert we generate expire a day
//        # before the user expected it to when they asked for "one year".
        DateTime notBefore = DateTime.now().minus(Period.days(1));
        DateTime notAfter = DateTime.now().plus(Period.years(5));

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                nextSerial(),
                notBefore.toDate(),
                notAfter.toDate(),
                certReq.getSubject(),
                certReq.getSubjectPublicKeyInfo());

        // TODO: add extensions to cert (maps to build_ca_extensions,
        //  build_server_extensions in certificate_factory.rb.
//
//        add_extensions_to(cert, csr, issuer, send(build_extensions))
//

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
        signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner signer = signerBuilder.build(issuerPrivateKey);

        X509CertificateHolder holder = builder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return converter.getCertificate(holder);
    }

    private BigInteger nextSerial() {
        // TODO: this needs to be able to persist between runs.
        int val = nextSerialNum.getAndIncrement();
        return BigInteger.valueOf(val);
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
