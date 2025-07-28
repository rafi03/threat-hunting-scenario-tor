# Detection Methodology

## Overview
This document outlines our systematic approach to detecting unauthorized TOR usage using Microsoft Defender for Endpoint.

## Detection Layers

### 1. File System Monitoring
- Monitor for TOR installer downloads
- Track file creation in non-standard locations
- Identify TOR configuration files

### 2. Process Analysis
- Detect silent installation attempts
- Track TOR service execution
- Monitor firefox.exe in TOR directories

### 3. Network Behavior
- Identify connections to TOR ports (9001, 9050, 9150)
- Monitor SOCKS proxy usage
- Track encrypted traffic patterns

## Query Development Process
1. Start with broad detection patterns
2. Refine based on false positives
3. Correlate across multiple data sources
4. Build timeline of events

## Success Metrics
- Detection time: < 5 minutes
- False positive rate: < 5%
- Coverage: All TOR variants