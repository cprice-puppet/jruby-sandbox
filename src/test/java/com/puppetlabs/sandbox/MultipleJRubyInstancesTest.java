package com.puppetlabs.sandbox;


import org.jruby.Ruby;
import org.jruby.RubyRuntimeAdapter;
import org.jruby.javasupport.JavaEmbedUtils;
import org.jruby.management.Runtime;
import org.jruby.runtime.builtin.IRubyObject;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.concurrent.*;

import static org.junit.Assert.assertTrue;



/**
 * Unit test for simple App.
 */
public class MultipleJRubyInstancesTest
{
    private static class RubyCallable implements Callable<IRubyObject> {

        private JavaEmbedUtils.EvalUnit evalUnit;

        private RubyCallable(JavaEmbedUtils.EvalUnit evalUnit) {
            this.evalUnit = evalUnit;
        }

        @Override
        public IRubyObject call() throws Exception {
            return evalUnit.run();
        }
    }


    @Test
    public void testApp() throws FileNotFoundException, ExecutionException, InterruptedException {
        ArrayList<String> loadPath1 = new ArrayList<String>();
        loadPath1.add("./src/test/resources/ruby/environment1/lib");
        Ruby ruby1 = JavaEmbedUtils.initialize(loadPath1);

        ArrayList<String> loadPath2 = new ArrayList<String>();
        loadPath2.add("./src/test/resources/ruby/environment2/lib");
        Ruby ruby2 = JavaEmbedUtils.initialize(loadPath2);

        RubyRuntimeAdapter adapter = JavaEmbedUtils.newRuntimeAdapter();

        JavaEmbedUtils.EvalUnit driver1 = adapter.parse(ruby1,
                new FileInputStream("./src/test/resources/ruby/driver.rb"),
                "driver.rb", 0);
        JavaEmbedUtils.EvalUnit driver2 = adapter.parse(ruby2,
                new FileInputStream("./src/test/resources/ruby/driver.rb"),
                "driver.rb", 0);

        FutureTask<IRubyObject> future1 = new FutureTask<IRubyObject>(new RubyCallable(driver1));
        FutureTask<IRubyObject> future2 = new FutureTask<IRubyObject>(new RubyCallable(driver2));

        ExecutorService executor = Executors.newFixedThreadPool(2);
        executor.execute(future1);
        executor.execute(future2);

        IRubyObject result2 = future2.get();
        IRubyObject result1 = future1.get();

        JavaEmbedUtils.invokeMethod(ruby1, result1, "printobject", new IRubyObject[] { result2 }, Object.class);
        JavaEmbedUtils.invokeMethod(ruby2, result2, "printobject", new IRubyObject[] { result1 }, Object.class);
        assertTrue(true);
    }
}
