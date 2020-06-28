FROM openjdk:8
VOLUME \tmp
EXPOSE 8090
ADD ./target/Service-gateway-0.0.1-SNAPSHOT.jar Microservice-Gateway.jar
ENTRYPOINT ["java","-jar","/Microservice-Gateway.jar"]