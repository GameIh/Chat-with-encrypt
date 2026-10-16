FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app app
COPY tests tests
COPY scripts scripts
RUN useradd --create-home messenger && mkdir /certs && chown messenger /certs
USER messenger
CMD ["python", "-m", "scripts.serve"]
