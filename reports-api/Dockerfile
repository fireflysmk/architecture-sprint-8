FROM openjdk:17-jdk-alpine
RUN apk add --no-cache curl
WORKDIR /app
ARG JAR_FILE=target/reports-api-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java", "-jar", "app.jar", "--spring.config.location=file:/config/application.yml"]