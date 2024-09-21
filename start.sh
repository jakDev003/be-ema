#!/bin/bash

# stop and remove all containers
docker compose down

docker compose up --build -d --force-recreate

echo "Done"
