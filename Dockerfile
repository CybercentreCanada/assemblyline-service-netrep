ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH netrep.netrep.NetRep

USER root

RUN apt update -y && apt upgrade -y
RUN pip install ail-typo-squatting

# Switch to assemblyline user
USER assemblyline

# Copy service code
WORKDIR /opt/al_service
COPY . .

USER root
RUN mv cloudflare-radar-domains-top-2000.csv /etc/top-2000.csv
ENV TOP_DOMAIN_CSV /etc/top-2000.csv

USER assemblyline

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
