FROM python:3.6-alpine

LABEL maintainer="swiftieterrence@outlook.com"

RUN pip install dnslib flask

COPY static/ /home/root/static/
COPY templates/ /home/root/templates/
COPY ./zones.txt /home/root/zones.txt
COPY ./app.py /home/root/app.py

WORKDIR /home/root

ENTRYPOINT ["python"]
CMD ["app.py"]
