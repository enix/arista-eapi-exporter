FROM python:3

RUN mkdir /arista-eapi-exporter
WORKDIR /arista-eapi-exporter

COPY ./requirements.txt ./
RUN pip install -r requirements.txt

COPY ./* ./

EXPOSE 9100/tcp

ENTRYPOINT ["python", "/arista-eapi-exporter/arista-eapi-exporter.py", "-a", "/arista-eapi-exporter/api_commands.yaml"]
CMD ["single", "-s", "unix"]