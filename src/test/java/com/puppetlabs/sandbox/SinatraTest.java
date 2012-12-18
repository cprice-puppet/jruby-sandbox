package com.puppetlabs.sandbox;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SinatraTest {
    @Test
    public void testSinatra() throws Exception {
        Server server = new Server(8080);

        String sinatraDir = "./src/test/resources/ruby/sinatra";
        WebAppContext webApp = new WebAppContext(sinatraDir, "/");
        webApp.setDescriptor(sinatraDir + "/WEB-INF/web.xml");
        webApp.setExtraClasspath(sinatraDir + "/bundler/jruby/1.9;" + sinatraDir + "/lib");

        server.setHandler(webApp);
        server.start();

//        Thread.sleep(2000);

        HttpClient client = new DefaultHttpClient();

        HttpGet request = new HttpGet("http://localhost:8080/");
        HttpResponse response = client.execute(request);

        String result = IOUtils.toString(response.getEntity().getContent());
        assertEquals("Expected response to be 'hello world'", result, "Hello World");

        server.stop();
        server.join();

//        Thread.sleep(2000);

    }
}
