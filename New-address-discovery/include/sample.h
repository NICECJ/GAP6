#ifndef SAMPLE_H
#define SAMPLE_H

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define NUM_HOPLIMITS MAX_HOPLIMIT_VALUES
#define NEIGHBOR_RADIUS 3
#define PRIOR_ALPHA 1.0
#define PRIOR_BETA 1.0
#define DECAY_FACTOR 0.01

// Generate a random number from the Beta distribution (approximate)
double beta_sample(double a, double b);

// Select the next hoplimit
int select_next_hoplimit(int index);

// Update observations and propagate the influence to neighboring hoplimits
void update_observations(int hoplimit, int index);

// Initialize the Beta distribution
void initialize(int index);

#endif
