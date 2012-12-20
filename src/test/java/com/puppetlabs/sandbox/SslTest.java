package com.puppetlabs.sandbox;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
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

    private static final String PATH_HOSTS_CERTS_DIR = PATH_TEST_DIR + "/certs";

    private static final AtomicInteger nextSerialNum = new AtomicInteger(1);

    private static abstract class AuthServlet extends HttpServlet
    {
        public AuthServlet(){}

        protected abstract void get(HttpServletRequest request, HttpServletResponse response) throws IOException;

        protected void put(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            super.doPut(request, response);
        }

        protected void checkAuth(HttpServletRequest request)
        {
            if (request.getAttribute("javax.servlet.request.X509Certificate") != null) {
                X509Certificate cert = ((X509Certificate[])(request.getAttribute("javax.servlet.request.X509Certificate")))[0];
                System.out.println("Got authenticated " + request.getMethod() + " request for '" + cert.getSubjectDN() + "' at URL '" + request.getRequestURI() + "'");
            } else {
                System.out.println("Got unauthenticated " + request.getMethod() + " request at URL '" + request.getRequestURI() + "'");
            }
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            checkAuth(request);
            get(request, response);
        }

        @Override
        protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            checkAuth(request);
            put(request, response);
        }
    }

    private static class FailServlet extends AuthServlet
    {
        @Override
        protected void get(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Unsupported URL path: '" + request.getPathInfo() + "'");
        }
    }

    private static class CACertServlet extends AuthServlet
    {
        @Override
        protected void get(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            IOUtils.copy(new FileReader(PATH_CA_CERT), response.getWriter());
        }
    }

    private static class CertServlet extends AuthServlet
    {
        @Override
        protected void get(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String host = request.getPathInfo().replaceFirst("/", "");
            File hostCertFile = new File(PATH_HOSTS_CERTS_DIR + "/" + host + ".pem");

            System.out.println("Looking for cert file: " + hostCertFile.getAbsolutePath());

            response.setContentType("text/plain");

            if (hostCertFile.exists()) {
                response.setStatus((HttpServletResponse.SC_OK));
                IOUtils.copy(new FileReader(hostCertFile), response.getWriter());
            } else {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                response.getWriter().print("Could not find certificate " + request.getPathInfo());
            }
        }
    }

    private static class CertReqServlet extends AuthServlet
    {
        @Override
        protected void get(HttpServletRequest request, HttpServletResponse response) throws IOException {

            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().print("Could not find certificate_request " + request.getPathInfo());
        }

        @Override
        protected void put(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            String host = request.getPathInfo().replaceFirst("/", "");
            String certReqString = IOUtils.toString(request.getInputStream());
//            System.out.println("CERT REQ PUT (for host '" + host + "':");
//            System.out.println(certReqString);
            PEMReader reader = new PEMReader(new StringReader(certReqString));
            PKCS10CertificationRequest certReq =
                    new PKCS10CertificationRequest(((org.bouncycastle.jce.PKCS10CertificationRequest) reader.readObject()).getEncoded());
            // TODO: we are just autosigning here, never saving the CSR to disk.

            X509Certificate cert;
            try {
                cert = signCertificateRequest(certReq, caName(), caPrivateKey());
            } catch (OperatorCreationException e) {
                throw new ServletException(e);
            } catch (CertificateException e) {
                throw new ServletException(e);
            }

            saveToPEM(cert, PATH_HOSTS_CERTS_DIR + "/" + host + ".pem");

            response.setContentType("text/yaml");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().print("--- \n  - !ruby/object:Puppet::SSL::CertificateRequest\n    name: " +
                    host + "\n    content: !ruby/object:OpenSSL::X509::Request {}\n    expiration: " +
                    // TODO: pull the *real* expiration date off of the cert req
                    DateTime.now().plus(Period.years(5)).toString());
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
        context.addServlet(new ServletHolder(new FailServlet()), "/*");
        context.addServlet(new ServletHolder(new CACertServlet()), "/production/certificate/ca");
        context.addServlet(new ServletHolder(new CertServlet()), "/production/certificate/*");
        context.addServlet(new ServletHolder(new CertReqServlet()), "/production/certificate_request/*");


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


        PKCS10CertificationRequest caCertReq = generateCertReq(caKeyPair, caName());
        X509Certificate caCert = signCertificateRequest(caCertReq, caName(), caKeyPair.getPrivate());
        saveToPEM(caCert, PATH_CA_CERT);

        KeyPair hostKeyPair = generateKeyPair();
        saveToPEM(hostKeyPair.getPublic(), PATH_MASTER_PUBLIC_KEY);
        saveToPEM(hostKeyPair.getPrivate(), PATH_MASTER_PRIVATE_KEY);

        X500Name hostName = generateX500Name(host);

        PKCS10CertificationRequest hostCertReq = generateCertReq(hostKeyPair, hostName);
        X509Certificate hostCert = signCertificateRequest(hostCertReq, caName(), caKeyPair.getPrivate());
        saveToPEM(hostCert, PATH_MASTER_CERT);

        // TODO: crl
//        # And make sure we initialize our CRL.
//                crl
    }

    private static X500Name caName() {
        // TODO: don't hard-code localhost
        return generateX500Name("Puppet CA: localhost");
    }

    private static PrivateKey caPrivateKey() throws IOException {
        PEMReader reader = new PEMReader(new FileReader(PATH_CA_PRIVATE_KEY));
        PrivateKey privateKey = ((KeyPair) reader.readObject()).getPrivate();
        return privateKey;
    }


    // TODO: It really sucks that the most specific type we can use
    //  here is 'Object'.
    private static void saveToPEM(Object pemObject, String filePath) throws IOException {
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

    private static X500Name generateX500Name(String commonName) {
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


    private static X509Certificate signCertificateRequest(PKCS10CertificationRequest certReq,
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

    private static BigInteger nextSerial() {
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
