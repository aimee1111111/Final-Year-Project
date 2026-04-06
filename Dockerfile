# Uses the official Python 3.11 slim image as the base image
FROM python:3.11-slim

# Sets the working directory inside the container
WORKDIR /app

# Copies the requirements file into the container
COPY requirements.txt /app/requirements.txt

# Installs all Python dependencies listed in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copies the rest of the project files into the container
COPY . /app

# Exposes port 5000 so the application can be accessed from outside the container
EXPOSE 5000

# Starts the Flask application by running Server.py
CMD ["python", "Server.py"]