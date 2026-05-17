#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Global configuration for the RFC parsing and IPv6 probe generation pipeline.
"""

# LLM / API Configuration
BASE_URL = "https://api.siliconflow.cn/v1"
API_URL = "https://api.siliconflow.cn/v1"
API_KEY = "sk-dpdlutirghtwgvgbdnzrblzkrkvidbngcpyyjftoknlnltpb"
MODEL = "deepseek-ai/DeepSeek-V3"
LLM_TEMPERATURE = 0.1

# RFC documents and output directories
RFC_FOLDER = "RFC"                 # Folder to store downloaded RFC documents
OUTPUT_DIR = "./ipv6_probes"       # Folder to store generated IPv6 probe mechanisms
OUTPUT_DIR_DEDUP = "./ipv6_probes_dedup" # Folder to store deduplicated mechanisms

# File processing settings
MAX_FILES_TO_PROCESS = 500         # Maximum number of files to process
MAX_TOKENS = 6000                  # Maximum tokens per processing batch

DOWNLOAD_START_RFC = 6000        # Start RFC number to download
DOWNLOAD_END_RFC = 6010            # End RFC number to download

ENABLE_REQUEST_INTERVAL = True     # Enable request interval to avoid server overload
REQUEST_INTERVAL = 10.0            # Interval between requests in seconds

SIMILARITY_THRESHOLD = 0.85  # Threshold for fuzzy deduplication (0 to 1, higher means more strict)

# Analysis workflow options
SKIP_ALREADY_ANALYZED_RFC = True   # Skip RFCs that have already been analyzed
RETRY_FAILED_RFC = False           # Retry RFCs that failed processing

# Logging
PROCESS_LOG_FILE = "process_log.json"  # Log file to track processing status