FROM python:3.12-slim
WORKDIR /app
COPY sdk/ /app/sdk/
RUN pip install --no-cache-dir /app/sdk/
COPY demo/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY demo/demo_api.py .
CMD ["uvicorn", "demo_api:app", "--host", "0.0.0.0", "--port", "8000"]
