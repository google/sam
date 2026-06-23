FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt /srv/
RUN pip install --no-cache-dir -r requirements.txt
COPY greeter_server.py /srv/

CMD ["python3", "/srv/greeter_server.py"]
