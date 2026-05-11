FROM python:3.12-slim

WORKDIR /workspace
COPY ./calc_server.py /workspace/calc_server.py
COPY ./requirements.txt /workspace/requirements.txt
RUN pip install -r requirements.txt

CMD ["python3", "/workspace/calc_server.py"]

