FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn>=0.29"
COPY . ./mock_server/
EXPOSE 8000
CMD ["uvicorn", "mock_server.app:app", "--host", "0.0.0.0", "--port", "8000"]