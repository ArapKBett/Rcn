FROM python:3.8

WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install system dependencies
RUN apt-get update && apt-get install -y \
    golang \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools
ENV PATH="/root/go/bin:${PATH}"
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/pentestpad/subzy@latest
RUN go install github.com/haccer/subjack@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install github.com/ffuf/ffuf@latest

# Install Git-based tools
RUN git clone https://github.com/FortyNorthSecurity/EyeWitness /app/EyeWitness
RUN git clone https://github.com/m4ll0k/SecretFinder /app/SecretFinder
RUN git clone https://github.com/maurosoria/dirsearch /app/dirsearch
RUN git clone https://github.com/sqlmapproject/sqlmap /app/sqlmap

# Install EyeWitness dependencies
RUN pip install -r /app/EyeWitness/Python/requirements.txt

# Expose Flask port
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
