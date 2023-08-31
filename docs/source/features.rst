IRIS-SOAR features
==============

IRIS-SOAR is currently still in early development. The following features are planned for the final release:

- Get detections from various sources (called 'integrations') and
  forward them to Znuny/OTRS

- Provide context for iris-cases by getting information from various
  sources ('integrations') and adding them to the iris_case. All this can be controlled on case-to case basis using 'playbooks'.

- Using playbooks it is also possible to automate actions on iris-cases. For
  example, if airis-caseis deemed to be a false positive, it can be closed automatically or if airis-caseis deemed to be a real incident, it can be escalated to a higher level of support.

- IRIS-SOAR is designed and build to be easily extensible. It is possible to
  add new integrations or playbooks to IRIS-SOAR with minimal effort.