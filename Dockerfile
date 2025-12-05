# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the SSL certificates to the container (ensure they are in the project directory)
COPY ./certs /app/certs

# Copy the application code
COPY . .

# Expose the HTTPS port (443)
EXPOSE 443
