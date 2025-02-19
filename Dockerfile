FROM cccs/assemblyline-v4-service-base:stable

ENV SERVICE_PATH=reversinglabsspectraintelligence.ReversingLabsSpectraIntelligence

# Install any service dependencies here
# For example: RUN apt-get update && apt-get install -y libyaml-dev
#              RUN pip install utils

# Switch to assemblyline user
USER assemblyline

RUN pip3 install reversinglabs-sdk-py3

# Copy ResultSample service code
WORKDIR /opt/al_service
COPY . .