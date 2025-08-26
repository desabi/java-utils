package com.desabi.guide.dynamic.proxies.examplea;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

// Step 3: Create an InvocationHandler that defines proxy behavior
class LoggingInvocationHandler implements InvocationHandler {
    private final Object target; // The actual object being proxied
    
    public LoggingInvocationHandler(Object target) {
        this.target = target;
    }
    
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        // Before method execution
        System.out.println("Start calling method: " + method.getName());
        
        // Call the actual method on the target object
        Object result = method.invoke(target, args);
        
        // After method execution
        System.out.println("End calling method: " + method.getName());

        return result;
    }
}
