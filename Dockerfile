# Use a lightweight Python image as the base
FROM python:3.9-slim

# Install git to clone the repository
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /goldrush

# Clone the GitHub repository (replace <username> and <repo> with actual names)
RUN git clone https://github.com/silviadefra/GolDRuSh .

# Install any required packages from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Set the entry point to run main.py as a command-line tool
ENTRYPOINT ["python", "goldrush.py"]
