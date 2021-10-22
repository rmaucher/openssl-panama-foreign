# OpenSSL wrapper using Panama

Clone https://github.com/openjdk/panama-foreign

bash configure
make images

Find include paths using "gcc -xc -E -v -"

export JAVA_HOME=/home/remm/Work/tomcat/panama-foreign/build/linux-x86_64-server-release/jdk
$JAVA_HOME/bin/jextract --source -t org.apache.tomcat.util.openssl -lssl -I /usr/lib/gcc/x86_64-redhat-linux/11/include openssl.h -d src/main/java

mvn package

cd target
$JAVA_HOME/bin/java --enable-native-access=ALL-UNNAMED --add-modules jdk.incubator.foreign -cp tomcat-openssl-0.1.jar org.apache.tomcat.util.net.openssl.panama.HelloOpenSSL

# Running in Tomcat

Copy tomcat-openssl-0.1.jar to lib folder.

Disable AprLifecycleListener.

Use a connector like: 
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
        <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
    </Connector>

export JAVA_HOME=/home/remm/Work/tomcat/panama-foreign/build/linux-x86_64-server-release/jdk
export JAVA_OPTS="--enable-native-access=ALL-UNNAMED --add-modules jdk.incubator.foreign"

