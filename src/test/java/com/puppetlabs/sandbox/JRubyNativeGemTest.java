package com.puppetlabs.sandbox;

import org.jruby.Ruby;
import org.jruby.RubyInstanceConfig;
import org.jruby.RubyRuntimeAdapter;
import org.jruby.javasupport.JavaEmbedUtils;
import org.junit.Test;

import java.util.ArrayList;

public class JRubyNativeGemTest {

    @Test
    public void testNativeGems() {
        String ruby_code =
                "require 'rubygems/command.rb'\n" +
                "require 'rubygems/dependency_installer.rb' \n" +
                "inst = Gem::DependencyInstaller.new\n" +
                "inst.install 'utf8'\n" +
                "require 'utf8'\n" +
                "s = String::UTF8.new\n" +
                "puts \"valid?: '#{s.valid?}'\"";

        System.out.println(RubyInstanceConfig.CEXT_ENABLED);

        RubyInstanceConfig ruby_config = new RubyInstanceConfig();
        ruby_config.setCextEnabled(true);

        Ruby ruby = JavaEmbedUtils.initialize(new ArrayList(), ruby_config);
        RubyRuntimeAdapter adapter = JavaEmbedUtils.newRuntimeAdapter();
        adapter.eval(ruby, ruby_code);
    }
}
