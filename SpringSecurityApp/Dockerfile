# Stage 1: Download dependencies
FROM eclipse-temurin:25-jdk-alpine AS dependency
RUN apk add --no-cache maven
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline

# Stage 2: Build the application
FROM dependency AS builder
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 3: Run the application
FROM eclipse-temurin:25-jre-alpine AS runtime
RUN apk add --no-cache curl
WORKDIR /app

# Copy JAR from builder
COPY --from=builder /build/target/*.jar app.jar

# Create logs folders
RUN mkdir -p /app/logs/archive && \
    chmod -R 755 /app/logs

# Create non-root user
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Document which port the app uses by dafult
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]