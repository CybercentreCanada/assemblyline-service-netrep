ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH netrep.netrep.NetRep

USER root

RUN apt update -y && apt install -y wget unzip
RUN pip install ail-typo-squatting tinydb

WORKDIR  /tmp
RUN wget https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip \
    && unzip top-1m.csv.zip \
    && mv top-1m.csv /etc/top-1m.csv \
    && rm top-1m.csv.zip


ENV TOP_1M_CSV /etc/top-1m.csv

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
