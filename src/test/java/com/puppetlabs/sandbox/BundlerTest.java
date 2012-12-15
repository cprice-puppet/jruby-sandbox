package com.puppetlabs.sandbox;

import org.jruby.Ruby;
import org.jruby.RubyRuntimeAdapter;
import org.jruby.javasupport.JavaEmbedUtils;
import org.junit.Test;

import java.util.ArrayList;

public class BundlerTest {
    @Test
    public void testBundler() {
        String ruby_code =
                "require 'bundler'\n" +
                "Bundler.settings[:path] = './src/test/resources/ruby/sinatra/bundler'\n" +
                "Bundler::Installer.install(Bundler.root, Bundler.definition)\n";


        Ruby ruby = JavaEmbedUtils.initialize(new ArrayList());
        RubyRuntimeAdapter adapter = JavaEmbedUtils.newRuntimeAdapter();
        adapter.eval(ruby, ruby_code);
    }

}
