#!/bin/bash

## General variables
GCP_ZONE_ID="us-east4-a"
GCP_NETWORK="default"
GCP_IMAGE="centos-7-v20201014"
GCP_PROJECT="tt-2021-009"

## Create project
gcloud config set project ${GCP_PROJECT}

### Creacion de Ip publica para Nginx y el Dns
# https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address
GCP_VM_NAME="cksrv01-1"

gcloud compute addresses create  ${GCP_VM_NAME}-address \
    --region="us-east4"

## Create router
GCP_VM_NAME="ckroute01-1"
gcloud compute routers create ${GCP_VM_NAME} \
    --network=${GCP_NETWORK} \
    --region="us-east4"

gcloud compute routers nats create ${GCP_VM_NAME}-nat \
    --router-region="us-east4" \
    --router=${GCP_VM_NAME} \
    --nat-all-subnet-ip-ranges \
    --auto-allocate-nat-external-ips

## Create Nginx and Dns vm
GCP_VM_NAME="cksrv01-1"
# https://cloud.google.com/compute/docs/machine-types#e2_machine_types
GCP_TYPE_MACHINE="e2-standard-2"

# https://cloud.google.com/sdk/gcloud/reference/compute/instances/create
gcloud compute instances create \
    --zone=${GCP_ZONE_ID} \
    --machine-type=${GCP_TYPE_MACHINE} \
    --preemptible \
    --image=${GCP_IMAGE} \
    --image-project="centos-cloud" \
    --boot-disk-size=25 \
    --network=${GCP_NETWORK} \
    --hostname=${GCP_VM_NAME}.neo.io \
    --address=${GCP_VM_NAME}-address \
    ${GCP_VM_NAME}

## Create Jenkins vm
GCP_VM_NAME="ckjnks01-1"
GCP_TYPE_MACHINE="n2-standard-2"

gcloud compute instances create \
    --zone=${GCP_ZONE_ID} \
    --machine-type=${GCP_TYPE_MACHINE} \
    --preemptible \
    --image=${GCP_IMAGE} \
    --image-project="centos-cloud" \
    --boot-disk-size=25 \
    --network=${GCP_NETWORK} \
    --hostname=${GCP_VM_NAME}.neo.io \
    --no-address \
    ${GCP_VM_NAME}

## Create deploy vm
GCP_VM_NAME="ckdply01-1"
GCP_TYPE_MACHINE="n2-standard-2"

gcloud compute instances create \
    --zone=${GCP_ZONE_ID} \
    --machine-type=${GCP_TYPE_MACHINE} \
    --preemptible \
    --image=${GCP_IMAGE} \
    --image-project="centos-cloud" \
    --boot-disk-size=25 \
    --network=${GCP_NETWORK} \
    --hostname=${GCP_VM_NAME}.neo.io \
    --no-address \
    ${GCP_VM_NAME}