# IRIS-SOAR

Welcome to IRIS-SOAR!

**IRIS-SOAR** is your go-to modular SOAR (Security Orchestration, Automation, and Response) solution, meticulously crafted with Python. Engineered to work seamlessly with DFIR-IRIS, it leverages playbook automation to facilitate effortless integrations with a variety of services.

Find the installation instructions [here](https://github.com/maof97/IRIS-SOAR/wiki/Installation-and-Setup).

To understand how IRIS-SOAR operates at a high level, visit our ["How it works"](https://github.com/maof97/IRIS-SOAR/wiki/How-it-works) wiki page.

Excited to contribute? Brilliant! All the information you need is on the [Contributing wiki page](https://github.com/maof97/IRIS-SOAR/wiki/Contributing).

## Features

Although IRIS-SOAR is in its early development stages, it promises a range of innovative features in its final release, including:

- Receiving and forwarding alerts from various integration points, converting them seamlessly into IRIS alerts.
- Enhancing IRIS-Cases with rich context gathered from different sources through integrations, managed efficiently using playbooks on a case-by-case basis.
- Automating the escalation or merging of one or more IRIS-Alerts into an IRIS-Case, directed by alert-specific playbooks.
- Facilitating automated actions on IRIS-Cases using case-specific playbooks — whether it's closing a false positive or escalating a genuine incident to a higher severity level.
- Easy extensibility allowing for the straightforward addition of new integrations or playbooks with minimal effort.

### Available Integrations

Here are the integrations available at the moment:

- **Elastic SIEM**: Facilitates the transition of alerts from Elastic to IRIS while also enhancing cases with Elastic data.
- **IBM QRadar**: Imports offenses from QRadar to IRIS as alerts and enrich cases with QRadar data.
- **VirusTotal**: Provides indicator threat intelligence context for individual cases or alerts.
- **Matrix**: Keeps users updated about alerts, new cases, and fresh findings.

Feel free to explore and make the most of IRIS-SOAR's evolving capabilities!
