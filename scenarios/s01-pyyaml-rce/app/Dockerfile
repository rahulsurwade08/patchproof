FROM python:3.11-slim

WORKDIR /srv
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock pytest "httpx==0.27.0"
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
