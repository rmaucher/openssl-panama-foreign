# OpenSSL wrapper using Panama

Clone https://github.com/openjdk/panama-foreign in some location

```
bash configure
make images
```

# Generating Panama OpenSSL API boilerplate code

Find include paths using "gcc -xc -E -v -", on Fedora it is /usr/lib/gcc/x86_64-redhat-linux/11/include

```
export JAVA_HOME=<pathto>/panama-foreign/build/linux-x86_64-server-release/jdk
$JAVA_HOME/bin/jextract --source -t org.apache.tomcat.util.openssl -lssl -I /usr/lib/gcc/x86_64-redhat-linux/11/include openssl.h -d src/main/java
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
