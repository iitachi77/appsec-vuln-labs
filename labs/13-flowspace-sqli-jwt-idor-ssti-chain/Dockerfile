FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The flag only ever lives in the process environment — reading it requires RCE.
ENV FLAG="FLAG{ch4in_1d0r_sql1_jwt_hm4c_ss7i_rce}"

EXPOSE 9011
CMD ["python", "app.py"]
