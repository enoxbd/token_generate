#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

// Root detect করবে
bool detectRoot();

// Frida detect করবে
bool detectFrida();

// Magisk detect করবে
bool detectMagisk();

// Burp Suite detect করবে
bool detectBurpSuite();

// HTTP Canary detect করবে
bool detectCanary();

// MITM Proxy detect করবে
bool detectMITM();

// Network proxy detect করবে (127.0.0.1)
bool detectProxy();

// App mod detect করবে
bool detectAppMod();

#endif
