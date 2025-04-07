                    # Use an official Python runtime as a parent image
FROM python:3.12-slim

# Prevent Python from writing pyc files to disc and enable stdout/stderr logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies (optional but recommended)
RUN apt-get update \
    && apt-get install -y libpq-dev gcc \
    && apt-get clean

# Copy the requirements file first to leverage Docker caching
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Collect static files (optional)
RUN python manage.py collectstatic --noinput

# Expose port 8080 (Cloud Run listens on this port)
EXPOSE 8000

# Run the application using Gunicorn (make sure Gunicorn is in requirements.txt)
CMD ["gunicorn", "name-project.wsgi:application", "--bind", "0.0.0.0:8080"]
