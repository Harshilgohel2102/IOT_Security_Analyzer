FROM python:3.11-slim
WORKDIR /app/server
COPY server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY server /app/server
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
