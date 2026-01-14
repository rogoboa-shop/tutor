# Stage 1: Build the Application
# We use a JDK image (not just JRE) to run the Gradle build
FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /app

# 1. Copy Gradle wrapper and configuration files first
# This allows Docker to cache dependencies if these files don't change
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
# Include settings.gradle if you have one (common in most projects)
COPY settings.gradle .

# 2. Grant execution permissions to the wrapper
RUN chmod +x ./gradlew

# 3. Copy the source code
COPY src src

# 4. Build the application
# 'bootJar' is specific to Spring Boot and creates the executable JAR.
# '-x test' skips tests to speed up deployment.
RUN ./gradlew clean bootJar -x test

# Stage 2: Run the Application
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Cloud Run handles the port automatically
ENV PORT=8080
EXPOSE 8080

# 5. Copy the built JAR
# Gradle outputs to 'build/libs/' instead of 'target/'
# We use a wildcard *.jar to avoid hardcoding the version
COPY --from=build /app/build/libs/*.jar app.jar

ENV SPRING_PROFILES_ACTIVE=prod

ENTRYPOINT ["java","-jar","app.jar"]