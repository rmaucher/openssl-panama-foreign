# OpenSSL wrapper using Panama

Clone https://github.com/openjdk/panama-foreign

bash configure
make images

Find include paths using "gcc -xc -E -v -"

export JAVA_HOME=/home/remm/Work/tomcat/panama-foreign/build/linux-x86_64-server-release/jdk
$JAVA_HOME/bin/jextract --source -t org.apache.tomcat.util.openssl -lssl -I /usr/lib/gcc/x86_64-redhat-linux/11/include openssl.h -d src/main/java

mvn package

$JAVA_HOME/bin/java --enable-native-access=ALL-UNNAMED --add-modules jdk.incubator.foreign -cp tomcat-openssl-0.1.jar org.apache.tomcat.util.net.openssl.panama.HelloOpenSSL
