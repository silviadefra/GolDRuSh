#!/bin/bash

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <volume_path>"
  exit 1
fi

NUM_CONTAINERS=30
VOLUME_PATH=$1
DOCKER_IMAGE="juliet"

# Build the Docker image
if [[ "$(docker images -q $DOCKER_IMAGE 2> /dev/null)" == "" ]]; then
  echo "Building Docker image..."
  docker build -t $DOCKER_IMAGE .
fi


TOTAL_FILES=$(ls -1q "$VOLUME_PATH/log_file/targets/" | wc -l)
FILES_PER_CONTAINER=$((TOTAL_FILES / NUM_CONTAINERS))
REMAINDER=$((TOTAL_FILES % NUM_CONTAINERS))

if [[ $TOTAL_FILES -lt $NUM_CONTAINERS ]]; then
  echo "Not enough files in the volume to distribute among containers"
  exit 1
fi

current_index=0

for i in $(seq 0 $((NUM_CONTAINERS - 1))); do
  if [[ $i -lt $REMAINDER ]]; then
    num_files=$((FILES_PER_CONTAINER + 1))
  else
    num_files=$FILES_PER_CONTAINER
  fi

  start_index=$current_index
  end_index=$((start_index + num_files - 1))

  current_index=$((end_index + 1))

  echo "Launching container N. $i with files from $start_index to $end_index"

  docker run --cpus="1" \
    --memory="2g" \
    -v "$VOLUME_PATH:/goldrush/log_file" \
    $DOCKER_IMAGE bash -c "
      for FILE in \$(ls log_file/targets | sed -n "$((start_index + 1)),$((end_index + 1))p"); do \
      python identify_vuln_functions.py log_file/targets/\$FILE;\
      done
    " >> "container_${i}.out" 2>&1 &
  done
done

wait
echo "All containers completed"

