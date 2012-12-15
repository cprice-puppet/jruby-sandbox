package com.puppetlabs.sandbox;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;
import org.junit.Test;

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
        server.join();

    }
}
