# Use a base image with Python 3.8
FROM python:3.8 AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.24.0
WORKDIR /go
RUN wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz && \
    rm go1.24.0.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install Go-based tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.7.1
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/PentestPad/subzy@latest
RUN go install github.com/haccer/subjack@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install github.com/ffuf/ffuf@latest

# Final stage
FROM python:3.8

WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Go binaries from builder stage
COPY --from=builder /root/go/bin /root/go/bin
ENV PATH="/root/go/bin:${PATH}"

# Install Git-based tools
RUN git clone https://github.com/FortyNorthSecurity/EyeWitness /app/EyeWitness && \
    pip install -r /app/EyeWitness/Python/requirements.txt
RUN git clone https://github.com/m4ll0k/SecretFinder /app/SecretFinder
RUN git clone https://github.com/maurosoria/dirsearch /app/dirsearch
RUN git clone https://github.com/sqlmapproject/sqlmap /app/sqlmap

# Install additional dependencies for EyeWitness
RUN apt-get update && apt-get install -y \
    python3-pyvirtualdisplay \
    firefox-esr \
    && rm -rf /var/lib/apt/lists/*

# Create Subfinder config directory and default config.yaml if not provided
RUN mkdir -p /root/.config/subfinder
RUN if [ ! -f config.yaml ]; then \
        echo "# Subfinder configuration file (default, add API keys)" > /root/.config/subfinder/config.yaml && \
        echo "censys:" >> /root/.config/subfinder/config.yaml && \
        echo "  - id: \"your-censys-id\"" >> /root/.config/subfinder/config.yaml && \
        echo "    secret: \"your-censys-secret\"" >> /root/.config/subfinder/config.yaml && \
        echo "shodan:" >> /root/.config/subfinder/config.yaml && \
        echo "  - \"your-shodan-api-key\"" >> /root/.config/subfinder/config.yaml && \
        echo "virustotal:" >> /root/.config/subfinder/config.yaml && \
        echo "  - \"your-virustotal-api-key\"" >> /root/.config/subfinder/config.yaml; \
    else \
        cp config.yaml /root/.config/subfinder/config.yaml; \
    fi
RUN chmod 600 /root/.config/subfinder/config.yaml

# Expose Flask port
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
