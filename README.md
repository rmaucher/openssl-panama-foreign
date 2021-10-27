# OpenSSL wrapper using Panama

Clone https://github.com/openjdk/panama-foreign in some location. This is a
forked Java 18 development JVM with the added Panama API and tools. It will
often fail to build. When this happens, step back one commit at a time until
it does. This is the only way to obtain the jextract tool, that is more or less
required for large libraries. The Panama API from this branch is also
different from the API present in Java 17.

```
bash configure
make images
```

# Generating Panama OpenSSL API boilerplate code

Find include paths using "gcc -xc -E -v -", on Fedora it is /usr/lib/gcc/x86_64-redhat-linux/11/include
Edit openssl.conf accordingly.

```
export JAVA_HOME=<pathto>/panama-foreign/build/linux-x86_64-server-release/jdk
$JAVA_HOME/bin/jextract @openssl-tomcat.conf openssl.h
```
The code included was generated for OpenSSL 1.1.1. As long as things remain API
compatible, this will still work. It is possible eventually to only generate code
for APIs that are actually used, but this is time consuming and can be done
later.

# Building

```
mvn package
```

# Running in Tomcat

Copy tomcat-openssl-X.X.jar to Tomcat lib folder.

Remove AprLifecycleListener.

Use a connector like:
```
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               SSLEnabled="true" scheme="https" secure="true"
               socket.directBuffer="false" socket.directSslBuffer="false"
               sslImplementationName="org.apache.tomcat.util.net.openssl.panama.OpenSSLImplementation">
        <SSLHostConfig certificateVerification="none">
            <Certificate certificateKeyFile="${catalina.home}/conf/localhost-rsa-key.pem"
                         certificateFile="${catalina.home}/conf/localhost-rsa-cert.pem"
                         certificateChainFile="${catalina.home}/conf/localhost-rsa-chain.pem"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
```
Run Tomcat using:
```
export JAVA_HOME=<pathto>/panama-foreign/build/linux-x86_64-server-release/jdk
export JAVA_OPTS="--enable-native-access=ALL-UNNAMED --add-modules jdk.incubator.foreign"
```
