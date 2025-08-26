package com.desabi.guide.dynamic.proxies.examplea;

import java.lang.reflect.Proxy;

// Step 4: Main class demonstrating dynamic proxy usage
// Dynamic proxies in Java allow you to create proxy objects at runtime
// that can intercept method calls and add custom behavior.
public class DynamicProxyExample {
    public static void main(String[] args) {
        // Create the actual object
        Calculator realCalculator = new SimpleCalculator();
        
        // Create the invocation handler
        LoggingInvocationHandler invocationHandler = new LoggingInvocationHandler(realCalculator);
        
        // Create the dynamic proxy
        Calculator proxyCalculator = (Calculator) Proxy.newProxyInstance(
            Calculator.class.getClassLoader(),    // ClassLoader
            new Class[]{Calculator.class},        // Interfaces to implement
            invocationHandler                     // InvocationHandler
        );
        
        // Use the proxy - method calls will be intercepted
        // Every method call on the proxy is redirected to the invoke() method
        // of the InvocationHandler.
        int sum = proxyCalculator.add(5, 3);
        int product = proxyCalculator.multiply(4, 6);
        
        System.out.println("Sum: " + sum);
        System.out.println("Product: " + product);
    }
}