Z-SOAR architecture
===================================

File Overview:

    The Z-SOAR core componets are:

        zsoar.py
            The main program, which starts the other components and handles
            the communication between them.

        zsoar_daemon.py (optional)
            A daemon process that runs in the background and starts the main zsoar.py on a regular interval.

        zsoar_setup.py
            Script that is used to install and/or configure the system.

    Modules:

        integrations/[INTEGRATION_NAME].py
            Integration modules that are used to communicate with the various
            services that Z-SOAR integrates with.

        playbooks/[PLAYBOOK_NAME].py
            Playbook modules that are used to define the actions that Z-SOAR
            takes when it detects an incident.

        configs/[CONFIG_NAME].yml
            Configuration files that are used to define the configuration
            settings for the various integrations and Z-SOAR itself.


