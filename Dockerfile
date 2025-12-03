FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography
WORKDIR /app
COPY xi_connect.py .
EXPOSE 54231 54230 54001
CMD ["python", "xi_connect.py"]
