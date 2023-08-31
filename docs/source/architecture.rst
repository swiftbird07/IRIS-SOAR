IRIS-SOAR architecture
===================================

File Overview:

    The IRIS-SOAR core componets are:

        isoar.py
            The main program, which starts the other components and handles
            the communication between them.

        isoar_daemon.py (optional)
            A daemon process that runs in the background and starts the main isoar.py on a regular interval.

        isoar_setup.py
            Script that is used to install and/or configure the system.

    Modules:

        integrations/[INTEGRATION_NAME].py
            Integration modules that are used to communicate with the various
            services that IRIS-SOAR integrates with.

        playbooks/[PLAYBOOK_NAME].py
            Playbook modules that are used to define the actions that IRIS-SOAR
            takes when it detects an incident.

        configs/[CONFIG_NAME].yml
            Configuration files that are used to define the configuration
            settings for the various integrations and IRIS-SOAR itself.


