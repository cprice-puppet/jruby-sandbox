package com.puppetlabs.sandbox;


import org.eclipse.jetty.util.ArrayQueue;

import java.util.ArrayList;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.*;

public class CpuLoadExperiment {

    private static class Worker {
        public synchronized double doWork(long duration) {
            System.out.println("Starting work");
            double x = 10.0f;
            long startTime = System.currentTimeMillis();
            Random rand = new Random(startTime);
            while (System.currentTimeMillis() - startTime < duration) {
                x = x + (10 * rand.nextDouble());
                x = x - (10 * rand.nextDouble());
//                System.out.println("x is now: " + x);
            }
            System.out.println("Work complete.");
            return x;
        }
    }

    private static class Runner implements Callable<Double> {
        private Worker w;

        private Runner(Worker w) {
            this.w = w;
        }

        @Override
        public Double call() throws Exception {
            return this.w.doWork(20000);
        }
    }



    public static void main(String[] args) throws ExecutionException, InterruptedException {
        final Worker worker = new Worker();

        Queue<FutureTask<Double>> tasks = new ArrayQueue<FutureTask<Double>>(5);

        ExecutorService executor = Executors.newFixedThreadPool(5);
        for (int i = 0; i < 5; i++) {
            Runner r = new Runner(worker);
            FutureTask<Double> task = new FutureTask<Double>(r);
            tasks.add(task);
            executor.execute(task);
        }

        while (! tasks.isEmpty()) {
            System.out.println(tasks.size() + " tasks remaining.");
            FutureTask<Double> task = tasks.remove();
            System.out.println("Grabbed a task from the queue, waiting for result.");
            Double result = task.get();
            System.out.println("Task completed with value: " + result);
        }

        executor.shutdown();
        while (! executor.isTerminated()) {
            System.out.println("Waiting for executor to shut down.");
        }

    }
}
