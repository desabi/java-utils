package com.desabi.guide.dynamic.proxies.examplea;

// Step 2: Create a concrete implementation
class SimpleCalculator implements Calculator {
    @Override
    public int add(int a, int b) {
        return a + b;
    }
    
    @Override
    public int multiply(int a, int b) {
        return a * b;
    }
}