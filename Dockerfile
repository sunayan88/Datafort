# Use Python 3.10 slim image
FROM python:3.10-slim

# Install system dependencies for Tkinter, MySQL client, and X11
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    default-libmysqlclient-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for Docker cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application
COPY . .

# Create directory for keys
RUN mkdir -p /root/.datafort

# Use Docker-specific database config
COPY config/docker_config.ini /app/config/config.ini

# Environment for GUI (X11)
ENV DISPLAY=:0
ENV QT_X11_NO_MITSHM=1

# Run the application
CMD ["python", "main.py"]