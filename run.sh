#!/bin/bash
#SBATCH --job-name=client-build
#SBATCH --partition=banana
#SBATCH --ntasks=1
#SBATCH --nodes=1
#SBATCH --exclusive
#SBATCH --time=00:05:00
#SBATCH --array=0-4

/clusterfs/ruzenkov/week15-16/client/build/client
