# IRIS-SOAR

Welcome!

**IRIS-SOAR** is a modular SOAR implementation written in Python. It is designed to be a companion to DFIR-IRIS that uses playbook automation and is able to load integrations to other services.

Check out the Usage section for information on how to setup and use the project.
Want to contribute? Nice! Check out the Contributing page for more information.

## IRIS-SOAR features

IRIS-SOAR is currently still in early development. The following features are planned for the final release:

- Get alerts from various sources (called ‘integrations’) and forward + convert them to IRIS alerts.
- Provide context for IRIS-Cases by getting information from various sources (‘integrations’) and adding them to the IRIS-Cases. All this can be controlled on case-to case basis using ‘playbooks’.
- Automatically escalate / merge one or multiple IRIS-Alerts to an IRIS-Case using alert specific playbooks.
- Using case specific playbooks it is also possible to automate actions on IRIS-Cases. For example, if an IRIS-Cases is deemed to be a false positive, it can be closed automatically or if the IRIS-Cases is deemed to be a real incident, it can be escalated to a severity etc..
- IRIS-SOAR is designed and build to be easily extensible. It is possible to add new integrations or playbooks to IRIS-SOAR with minimal effort.
