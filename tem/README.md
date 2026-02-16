# TEM

TEM (Threat Exposure Management) is a tool designed to generate structured presentations of penetration-testing results. It consumes RSSD files exported from EAA (Enterprise Asset Assessment) and enhances them using:

- Custom SQL views and queries  
- Surveilr integrations  
- Markdown-based interpretations created via Backlog and ingested into the database  

The system aggregates, processes, and enriches assessment data, allowing TEM to clearly present which findings are actionable, how they should be interpreted, and which items can be safely disregarded. This results in a cleaner, more understandable view of security issues for reporting and analysis.

## Download [Spry](https://sprymd.org/)

```bash
wget https://github.com/programmablemd/packages/releases/download/latest/spry-ubuntu22.04u1_amd64.deb
sudo dpkg -i spry-ubuntu22.04u1_amd64.deb
```

## Command to run

```bash
spry rb run Spryfile.md --verbose rich
```
- Note: Ensure the RSSD file (sqlite.db) is placed inside this repository before running the above command.
